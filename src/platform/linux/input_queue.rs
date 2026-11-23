//! A bounded queue of whole input records between where a host source
//! produces them and the step that writes them to a channel.
//!
//! A channel write is whole or refused. `relay` keeps a refused record at
//! the front and offers it again on the next step, so a full channel delays
//! input and never loses it; only a queue that is itself full drops, oldest
//! first, and counts what it dropped.

use std::collections::VecDeque;

use crate::abi::contracts::input::pointer;

/// Records a queue holds before the oldest is dropped.
pub const QUEUE_RECORDS: usize = 64;

/// A bounded queue of whole records between the window thread and the
/// step. When it is full the oldest record is dropped and counted.
#[derive(Default)]
pub struct RecordQueue {
    records: VecDeque<Vec<u8>>,
    dropped: u32,
}

impl RecordQueue {
    pub fn push(&mut self, record: &[u8]) {
        if self.records.len() >= QUEUE_RECORDS {
            self.records.pop_front();
            self.dropped = self.dropped.wrapping_add(1);
        }
        self.records.push_back(record.to_vec());
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Records dropped because the queue was full.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Hand records to `write`, oldest first, while it takes them. A record
    /// `write` refuses stays at the front for the next call.
    pub fn relay(&mut self, mut write: impl FnMut(&[u8]) -> bool) {
        while let Some(front) = self.records.front() {
            if !write(front) {
                return;
            }
            self.records.pop_front();
        }
    }

    /// Add a wheel movement, summed into the newest queued record when that
    /// is a wheel record of the same pointer, unit, buttons and modifiers:
    /// between two relays a pointer sends one wheel record a unit. A sum
    /// past a record's range continues in a further record.
    pub fn push_wheel(&mut self, wheel: &Wheel) {
        let (mut dx, mut dy) = (wheel.dx, wheel.dy);
        if dx == 0 && dy == 0 {
            return;
        }
        if let Some(back) = self.records.back_mut() {
            let prior = <&[u8; pointer::EVENT_SIZE]>::try_from(back.as_slice())
                .ok()
                .and_then(pointer::decode)
                .filter(|e| {
                    e.kind == pointer::KIND_WHEEL
                        && e.wheel_unit == wheel.unit
                        && e.pointer_id == wheel.pointer_id
                        && e.buttons == wheel.buttons
                        && e.modifiers == wheel.modifiers
                });
            if let Some(prior) = prior {
                let sum_x = i32::from(prior.dx) + dx;
                let sum_y = i32::from(prior.dy) + dy;
                let merged = pointer::Event {
                    x: wheel.x,
                    y: wheel.y,
                    dx: sum_x.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
                    dy: sum_y.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
                    ..prior
                };
                if let Some(bytes) = pointer::encode(&merged) {
                    back.copy_from_slice(&bytes);
                    dx = sum_x - i32::from(merged.dx);
                    dy = sum_y - i32::from(merged.dy);
                }
            }
        }
        while dx != 0 || dy != 0 {
            let part_x = dx.clamp(i32::from(i16::MIN), i32::from(i16::MAX));
            let part_y = dy.clamp(i32::from(i16::MIN), i32::from(i16::MAX));
            let event = pointer::Event {
                pointer_id: wheel.pointer_id,
                kind: pointer::KIND_WHEEL,
                buttons: wheel.buttons,
                modifiers: wheel.modifiers,
                wheel_unit: wheel.unit,
                pressure: 0,
                x: wheel.x,
                y: wheel.y,
                dx: part_x as i16,
                dy: part_y as i16,
            };
            let Some(bytes) = pointer::encode(&event) else {
                return;
            };
            self.push(&bytes);
            dx -= part_x;
            dy -= part_y;
        }
    }
}

/// One wheel movement, in the record's units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wheel {
    pub pointer_id: u8,
    /// `pointer::WHEEL_PIXELS` or `pointer::WHEEL_DETENTS`.
    pub unit: u8,
    pub buttons: u8,
    pub modifiers: u8,
    pub x: i16,
    pub y: i16,
    pub dx: i32,
    pub dy: i32,
}
