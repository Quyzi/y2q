//! RFC 7231 (`Last-Modified`/`If-Modified-Since`/etc.) date formatting and
//! parsing, and the Howard Hinnant civil-calendar conversions it's built on.
//! No dependency on `chrono` or any other date crate — the arithmetic is
//! ~20 lines each way and this is the only place in the daemon that needs
//! calendar dates rather than raw Unix timestamps.

use std::time::{SystemTime, UNIX_EPOCH};

/// Days-since-epoch (1970-01-01 = 0) -> proleptic-Gregorian `(year, month, day)`.
/// Inverse of the `days_from_civil` used by `crate::s3::sigv4::parse_amz_date`.
/// See <https://howardhinnant.github.io/date_algorithms.html>.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 13] = [
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format `unix_secs` as an RFC 7231 IMF-fixdate (`Last-Modified` shape):
/// `"Sun, 06 Nov 1994 08:49:37 GMT"`.
pub fn http_date(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    let (y, m, d) = civil_from_days(days);
    // 1970-01-01 (days == 0) was a Thursday (weekday index 4, Sunday == 0).
    let weekday = ((days % 7 + 7) + 4) % 7;
    format!(
        "{}, {d:02} {} {y} {hour:02}:{minute:02}:{second:02} GMT",
        WEEKDAYS[weekday as usize], MONTHS[m as usize]
    )
}

/// Format `unix_secs` as the ISO 8601 UTC form S3 XML response bodies use
/// for `LastModified`/`CreationDate` (distinct from the RFC 7231 form HTTP
/// headers use): `"2006-01-02T15:04:05.000Z"`.
pub fn iso8601(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.000Z")
}

/// [`iso8601`] from a `SystemTime` (clamped to the Unix epoch if earlier).
pub fn iso8601_from(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso8601(secs)
}

/// Parse an RFC 7231 IMF-fixdate. Returns `None` for any other HTTP-date
/// grammar (obsolete RFC 850 / asctime forms) or malformed input — callers
/// treat an unparseable conditional-request date as absent, per RFC 9110's
/// guidance to ignore a malformed precondition header.
pub fn parse_http_date(s: &str) -> Option<SystemTime> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month = MONTHS.iter().position(|m| *m == parts[2])? as u32;
    let year: i64 = parts[3].parse().ok()?;
    let mut time_parts = parts[4].split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || parts[5] != "GMT" {
        return None;
    }
    if !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)?;
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_matches_known_value() {
        // 1994-11-06T08:49:37Z
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn http_date_round_trips_through_parse() {
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_735_689_600);
        let formatted = http_date(1_735_689_600);
        let parsed = parse_http_date(&formatted).unwrap();
        assert_eq!(parsed, t);
    }

    #[test]
    fn parse_http_date_rejects_garbage() {
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("Sun, 06 Nov 1994 08:49:37 EST").is_none());
    }
}
