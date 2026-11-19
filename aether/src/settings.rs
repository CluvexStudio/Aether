use std::collections::HashMap;
use std::env::VarError;
use std::sync::{LazyLock, PoisonError, RwLock};

static SET: LazyLock<RwLock<HashMap<String, Option<String>>>> = LazyLock::new(Default::default);

pub fn var(key: impl AsRef<str>) -> Result<String, VarError> {
    let key = key.as_ref();
    let set = SET.read().unwrap_or_else(PoisonError::into_inner);
    match set.get(key) {
        Some(Some(value)) => Ok(value.clone()),
        Some(None) => Err(VarError::NotPresent),
        None => std::env::var(key),
    }
}

pub fn set(key: impl AsRef<str>, value: impl AsRef<str>) {
    SET.write()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key.as_ref().to_string(), Some(value.as_ref().to_string()));
}

pub fn remove(key: impl AsRef<str>) {
    SET.write()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key.as_ref().to_string(), None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_setting_shadows_the_environment_and_a_removal_hides_it() {
        let key = "AETHER_SETTINGS_TEST_ONLY";
        assert_eq!(var(key), Err(VarError::NotPresent));

        set(key, "on");
        assert_eq!(var(key).as_deref(), Ok("on"));

        set(key, String::from("off"));
        assert_eq!(var(key).as_deref(), Ok("off"));

        remove(key);
        assert_eq!(var(key), Err(VarError::NotPresent));
    }

    #[test]
    fn an_untouched_key_is_read_from_the_environment() {
        let path = std::env::var("PATH");
        assert_eq!(var("PATH"), path);
    }
}
