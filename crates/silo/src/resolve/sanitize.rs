use super::hash::{FNV_OFFSET, FNV_PRIME};

pub fn sanitize_name(raw: &str) -> String {
    let ascii_part: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    if !raw.is_ascii() || (!raw.is_empty() && ascii_part.is_empty()) {
        let mut hash = FNV_OFFSET;
        for &b in raw.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        let suffix = format!("{:08x}", hash as u32);
        if ascii_part.is_empty() {
            suffix
        } else {
            format!("{ascii_part}-{suffix}")
        }
    } else {
        ascii_part
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_basic() {
        assert_eq!(sanitize_name("feature/auth"), "feature-auth");
        assert_eq!(sanitize_name("main"), "main");
        assert_eq!(sanitize_name("my_branch"), "my_branch");
    }

    #[test]
    fn sanitize_collapses_dashes() {
        assert_eq!(sanitize_name("a//b"), "a-b");
        assert_eq!(sanitize_name("a---b"), "a-b");
    }

    #[test]
    fn sanitize_strips_leading_trailing() {
        assert_eq!(sanitize_name("/feature/"), "feature");
        assert_eq!(sanitize_name("--main--"), "main");
    }

    #[test]
    fn sanitize_dots_and_special() {
        assert_eq!(sanitize_name("release/v1.0.0"), "release-v1-0-0");
        assert_eq!(sanitize_name("feat@thing"), "feat-thing");
    }

    #[test]
    fn sanitize_name_empty() {
        assert_eq!(sanitize_name(""), "");
    }

    #[test]
    fn sanitize_name_all_special() {
        assert!(!sanitize_name("///...///").is_empty());
        assert_ne!(sanitize_name("///"), sanitize_name("..."));
        assert_ne!(sanitize_name("@@@"), sanitize_name("+++"));
    }

    #[test]
    fn sanitize_name_unicode() {
        let result = sanitize_name("기능/인증");
        assert!(!result.is_empty());
        assert!(!result.contains('/'));
        assert!(!result.contains("--"));
        assert_ne!(sanitize_name("기능/인증"), sanitize_name("기능/로그인"));
        assert_ne!(sanitize_name("기능/인증"), sanitize_name("버그/수정"));
    }

    #[test]
    fn sanitize_name_mixed_unicode_ascii() {
        let result = sanitize_name("feature/인증");
        assert!(result.starts_with("feature-"));
        assert_ne!(result, "feature");
        assert_ne!(
            sanitize_name("feature/인증"),
            sanitize_name("feature/로그인")
        );
    }

    #[test]
    fn sanitize_name_unicode_languages() {
        let names = [
            "기능/인증",
            "機能/認証",
            "フィーチャー/認証",
            "功能/认证",
            "功能/認證",
            "фича/авторизация",
            "функція/авторизація",
            "özellik/kimlik",
            "tính-năng/xác-thực",
            "ميزة/مصادقة",
            "תכונה/אימות",
            "ฟีเจอร์/ยืนยัน",
            "सुविधा/प्रमाणीकरण",
        ];
        let sanitized: Vec<String> = names.iter().map(|n| sanitize_name(n)).collect();
        for (name, result) in names.iter().zip(&sanitized) {
            assert!(!result.is_empty(), "{name} sanitized to empty");
        }
        let unique: std::collections::HashSet<&String> = sanitized.iter().collect();
        assert_eq!(
            unique.len(),
            sanitized.len(),
            "collision among: {:?}",
            sanitized
        );
    }
}
