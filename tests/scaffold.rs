use judge::ProviderCallTimeout;

#[test]
fn provider_deadline_rejects_zero_milliseconds() {
    assert!(ProviderCallTimeout::from_milliseconds(0).is_err());
    assert_eq!(
        ProviderCallTimeout::from_milliseconds(1)
            .unwrap()
            .duration()
            .as_millis(),
        1
    );
}
