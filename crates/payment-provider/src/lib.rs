//! Payment provider boundary and deterministic manual provider.
//!
//! Providers return domain events instead of mutating subscriptions directly.
//! Callers must persist the resulting order/payment transition transactionally.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderStatus {
    Pending,
    Paid,
    Cancelled,
    Refunded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentOrder {
    pub id: Uuid,
    pub idempotency_key: String,
    pub amount_cents: i64,
    pub currency: String,
    pub status: OrderStatus,
    pub provider: String,
    pub provider_payment_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentEvent {
    pub provider_payment_id: String,
    pub status: OrderStatus,
    pub idempotency_key: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PaymentError {
    #[error("amount must be positive")]
    InvalidAmount,
    #[error("currency must not be empty")]
    InvalidCurrency,
    #[error("order not found")]
    NotFound,
    #[error("invalid order state for this operation")]
    InvalidState,
    #[error("callback signature is invalid")]
    InvalidCallback,
    #[error("idempotency key is already used with different parameters")]
    IdempotencyConflict,
}

pub trait PaymentProvider: Send + Sync {
    fn create_order(
        &self,
        amount_cents: i64,
        currency: &str,
        idempotency_key: &str,
    ) -> Result<PaymentOrder, PaymentError>;
    fn query_order(&self, order_id: Uuid) -> Result<PaymentOrder, PaymentError>;
    fn verify_callback(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<PaymentEvent, PaymentError>;
    fn refund(&self, order_id: Uuid) -> Result<PaymentOrder, PaymentError>;
}

#[derive(Clone, Default)]
pub struct ManualPaymentProvider {
    orders: Arc<Mutex<HashMap<Uuid, PaymentOrder>>>,
    keys: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl ManualPaymentProvider {
    pub fn mark_paid(&self, order_id: Uuid) -> Result<PaymentOrder, PaymentError> {
        let mut orders = self.orders.lock().expect("payment provider lock poisoned");
        let order = orders.get_mut(&order_id).ok_or(PaymentError::NotFound)?;
        if order.status != OrderStatus::Pending {
            return Err(PaymentError::InvalidState);
        }
        order.status = OrderStatus::Paid;
        order.provider_payment_id = Some(format!("manual-{}", order.id));
        Ok(order.clone())
    }

    fn callback_signature(payload: &[u8]) -> String {
        // Manual provider callbacks are local-only. Production providers must
        // implement their own authenticated signature verification.
        payload.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl PaymentProvider for ManualPaymentProvider {
    fn create_order(
        &self,
        amount_cents: i64,
        currency: &str,
        idempotency_key: &str,
    ) -> Result<PaymentOrder, PaymentError> {
        if amount_cents <= 0 {
            return Err(PaymentError::InvalidAmount);
        }
        if currency.trim().is_empty() {
            return Err(PaymentError::InvalidCurrency);
        }
        let mut keys = self.keys.lock().expect("payment provider lock poisoned");
        if let Some(order_id) = keys.get(idempotency_key).copied() {
            let order = self
                .orders
                .lock()
                .expect("payment provider lock poisoned")
                .get(&order_id)
                .cloned()
                .ok_or(PaymentError::NotFound)?;
            if order.amount_cents != amount_cents || order.currency != currency {
                return Err(PaymentError::IdempotencyConflict);
            }
            return Ok(order);
        }
        let order = PaymentOrder {
            id: Uuid::new_v4(),
            idempotency_key: idempotency_key.to_owned(),
            amount_cents,
            currency: currency.to_owned(),
            status: OrderStatus::Pending,
            provider: "manual".to_owned(),
            provider_payment_id: None,
        };
        keys.insert(idempotency_key.to_owned(), order.id);
        self.orders
            .lock()
            .expect("payment provider lock poisoned")
            .insert(order.id, order.clone());
        Ok(order)
    }

    fn query_order(&self, order_id: Uuid) -> Result<PaymentOrder, PaymentError> {
        self.orders
            .lock()
            .expect("payment provider lock poisoned")
            .get(&order_id)
            .cloned()
            .ok_or(PaymentError::NotFound)
    }

    fn verify_callback(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<PaymentEvent, PaymentError> {
        if Self::callback_signature(payload) != signature {
            return Err(PaymentError::InvalidCallback);
        }
        let key = std::str::from_utf8(payload).map_err(|_| PaymentError::InvalidCallback)?;
        let order_id = self
            .keys
            .lock()
            .expect("payment provider lock poisoned")
            .get(key)
            .copied()
            .ok_or(PaymentError::NotFound)?;
        let order = self.mark_paid(order_id)?;
        Ok(PaymentEvent {
            provider_payment_id: order.provider_payment_id.unwrap_or_default(),
            status: order.status,
            idempotency_key: order.idempotency_key,
        })
    }

    fn refund(&self, order_id: Uuid) -> Result<PaymentOrder, PaymentError> {
        let mut orders = self.orders.lock().expect("payment provider lock poisoned");
        let order = orders.get_mut(&order_id).ok_or(PaymentError::NotFound)?;
        if order.status != OrderStatus::Paid {
            return Err(PaymentError::InvalidState);
        }
        order.status = OrderStatus::Refunded;
        Ok(order.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{ManualPaymentProvider, OrderStatus, PaymentError, PaymentProvider};

    #[test]
    fn create_is_idempotent_and_rejects_parameter_reuse() {
        let provider = ManualPaymentProvider::default();
        let first = provider.create_order(100, "CNY", "order-1").unwrap();
        assert_eq!(
            provider.create_order(100, "CNY", "order-1").unwrap().id,
            first.id
        );
        assert_eq!(
            provider.create_order(200, "CNY", "order-1"),
            Err(PaymentError::IdempotencyConflict)
        );
    }

    #[test]
    fn manual_payment_transitions_pending_paid_refunded() {
        let provider = ManualPaymentProvider::default();
        let order = provider.create_order(100, "CNY", "order-2").unwrap();
        assert_eq!(order.status, OrderStatus::Pending);
        assert_eq!(
            provider.mark_paid(order.id).unwrap().status,
            OrderStatus::Paid
        );
        assert_eq!(
            provider.refund(order.id).unwrap().status,
            OrderStatus::Refunded
        );
        assert_eq!(provider.refund(order.id), Err(PaymentError::InvalidState));
    }

    #[test]
    fn callback_signature_is_verified_and_idempotent_state_is_reused() {
        let provider = ManualPaymentProvider::default();
        let order = provider.create_order(100, "CNY", "order-3").unwrap();
        let payload = b"order-3";
        let signature = payload
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let event = provider.verify_callback(payload, &signature).unwrap();
        assert_eq!(event.status, OrderStatus::Paid);
        assert_eq!(
            provider.query_order(order.id).unwrap().status,
            OrderStatus::Paid
        );
        assert_eq!(
            provider.verify_callback(payload, "bad"),
            Err(PaymentError::InvalidCallback)
        );
    }
}
