/**
 * Parse a given time string into milliseconds. This can be used to convert a
 * string such as '20ms', '10s' or '1h' into adequate milliseconds. Without
 * suffix, the default behavior is to parse into milliseconds.
 */
pub fn parse_to_milliseconds(time_arg: &str) -> Result<u64, &str> {
    let len = time_arg.len();

    if time_arg.ends_with("ms") {
        let milliseconds_text = &time_arg[0..len - 2];
        return match milliseconds_text.parse::<u64>() {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid milliseconds"),
        };
    }

    if time_arg.ends_with('s') {
        let seconds_text = &time_arg[0..len - 1];
        return match seconds_text.parse::<u64>().map(|value| value * 1000) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid seconds"),
        };
    }

    if time_arg.ends_with('m') {
        let seconds_text = &time_arg[0..len - 1];
        return match seconds_text.parse::<u64>().map(|value| value * 1000 * 60) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid minutes"),
        };
    }

    if time_arg.ends_with('h') {
        let hour_text = &time_arg[0..len - 1];
        return match hour_text.parse::<u64>().map(|value| value * 1000 * 60 * 60) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid hours"),
        };
    }

    match time_arg.parse::<u64>() {
        Ok(ms_value) => Ok(ms_value),
        Err(_) => Err("invalid milliseconds"),
    }
}

/**
 * Format milliseconds to a human-readable string. This will of course give an
 * approximation, but will be readable.
 */
pub fn format_milliseconds(milliseconds: u128) -> String {
    if milliseconds < 1000 {
        return format!("{}ms", milliseconds);
    }

    if milliseconds < 1000 * 60 {
        let seconds = milliseconds / 1000;
        return format!("{}s", seconds);
    }

    if milliseconds < 1000 * 60 * 60 {
        let minutes = milliseconds / 1000 / 60;
        return format!("{}m", minutes);
    }

    let hours: u128 = milliseconds / 1000 / 60 / 60;
    format!("{}h", hours)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_parse_milliseconds() {
        assert_eq!(parse_to_milliseconds("1000"), Ok(1000));
    }

    #[test]
    fn should_parse_seconds() {
        assert_eq!(parse_to_milliseconds("5s"), Ok(5000));
    }

    #[test]
    fn should_parse_minutes() {
        assert_eq!(parse_to_milliseconds("3m"), Ok(180_000));
    }

    #[test]
    fn should_parse_hours() {
        assert_eq!(parse_to_milliseconds("2h"), Ok(7_200_000));
    }

    #[test]
    fn should_deny_negative() {
        assert_eq!(parse_to_milliseconds("-45"), Err("invalid milliseconds"));
    }

    #[test]
    fn should_deny_floating_numbers() {
        assert_eq!(parse_to_milliseconds("3.235"), Err("invalid milliseconds"));
    }

    #[test]
    fn should_deny_invalid_characters() {
        assert_eq!(parse_to_milliseconds("3z"), Err("invalid milliseconds"));
    }

    // ---

    #[test]
    fn should_display_milliseconds() {
        assert_eq!(format_milliseconds(500), "500ms".to_string());
    }

    #[test]
    fn should_display_seconds() {
        assert_eq!(format_milliseconds(2500), "2s".to_string());
    }

    #[test]
    fn should_display_minutes() {
        assert_eq!(format_milliseconds(300_000), "5m".to_string());
    }

    #[test]
    fn should_display_hours() {
        assert_eq!(format_milliseconds(4_200_000), "1h".to_string());
    }
}
