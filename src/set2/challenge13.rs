struct Profile {
    uid: u32,
    email: String,
    role: String,
}

impl Profile {

    pub fn new(email: String) -> Profile {
        Profile {
            email: email,
            uid: 10,
            role: "user".to_string(),
        }

    }

}

impl ToString for Profile {
    fn to_string(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }
}

#[test]
fn profile_prints_url_formatted() {
    let test_prof = Profile::new("foo@bar.com".to_string());
    assert_eq!(test_prof.to_string(),
    "email=foo@bar.com&uid=10&role=user");
}
