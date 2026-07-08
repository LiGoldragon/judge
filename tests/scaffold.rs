use judge::RetryPolicy;

#[test]
fn retry_policy_rejects_zero_attempts() {
    assert!(RetryPolicy::new(0).is_err());
    assert_eq!(RetryPolicy::new(1).unwrap().maximum_attempts().get(), 1);
}
