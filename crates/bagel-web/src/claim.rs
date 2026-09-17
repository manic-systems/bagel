use std::fmt::{
   Display,
   Formatter,
   Result as FmtResult,
};

/// Browser family a `User-Agent` header claims to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
   Chrome,
   Edge,
   Firefox,
   Safari,
   Opera,
   Samsung,
   Yandex,
}

impl Family {
   const fn as_str(self) -> &'static str {
      match self {
         Self::Chrome => "chrome",
         Self::Edge => "edge",
         Self::Firefox => "firefox",
         Self::Safari => "safari",
         Self::Opera => "opera",
         Self::Samsung => "samsung",
         Self::Yandex => "yandex",
      }
   }
}

impl Display for Family {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      formatter.write_str(self.as_str())
   }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
   Windows,
   MacOs,
   Ios,
   Android,
   ChromeOs,
   Linux,
   Unknown,
}

impl Platform {
   const fn as_str(self) -> &'static str {
      match self {
         Self::Windows => "windows",
         Self::MacOs => "macos",
         Self::Ios => "ios",
         Self::Android => "android",
         Self::ChromeOs => "chromeos",
         Self::Linux => "linux",
         Self::Unknown => "unknown",
      }
   }

   fn detect(user_agent: &str) -> Self {
      if user_agent.contains("Windows") {
         Self::Windows
      } else if user_agent.contains("Android") {
         Self::Android
      } else if ["iPhone", "iPad", "iPod"]
         .iter()
         .any(|device| user_agent.contains(device))
      {
         Self::Ios
      } else if user_agent.contains("CrOS") {
         Self::ChromeOs
      } else if user_agent.contains("Macintosh") || user_agent.contains("Mac OS X") {
         Self::MacOs
      } else if user_agent.contains("Linux") || user_agent.contains("X11") {
         Self::Linux
      } else {
         Self::Unknown
      }
   }
}

impl Display for Platform {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      formatter.write_str(self.as_str())
   }
}

/// A recognised browser claim. Everything else, tools and crawlers
/// included, parses to `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Claim {
   pub family:   Family,
   pub major:    u16,
   pub platform: Platform,
   pub mobile:   bool,
}

impl Claim {
   #[must_use]
   pub fn parse(user_agent: &str) -> Option<Self> {
      if user_agent.len() > 1024 || !user_agent.starts_with("Mozilla/5.0") {
         return None;
      }
      let (family, major) = if let Some(major) = product_major(user_agent, "Edg/") {
         (Family::Edge, major)
      } else if let Some(major) = product_major(user_agent, "OPR/") {
         (Family::Opera, major)
      } else if let Some(major) = product_major(user_agent, "SamsungBrowser/") {
         (Family::Samsung, major)
      } else if let Some(major) = product_major(user_agent, "YaBrowser/") {
         (Family::Yandex, major)
      } else if let Some(major) = product_major(user_agent, "Firefox/")
         && user_agent.contains("Gecko/")
      {
         (Family::Firefox, major)
      } else if let Some(major) = product_major(user_agent, "FxiOS/") {
         (Family::Firefox, major)
      } else if let Some(major) = product_major(user_agent, "CriOS/") {
         (Family::Chrome, major)
      } else if let Some(major) = product_major(user_agent, "Chrome/") {
         (Family::Chrome, major)
      } else if let Some(major) = product_major(user_agent, "Version/")
         && user_agent.contains("Safari/")
      {
         (Family::Safari, major)
      } else {
         return None;
      };
      Some(Self {
         family,
         major,
         platform: Platform::detect(user_agent),
         mobile: user_agent.contains("Mobile") || user_agent.contains("iPhone"),
      })
   }

   /// The TLS stack this claim implies, named like `fp["edge_family"]`.
   /// Every browser on iOS uses Apple's stack regardless of brand.
   #[must_use]
   pub const fn stack(&self) -> &'static str {
      match (self.platform, self.family) {
         (Platform::Ios, _) | (_, Family::Safari) => "safari",
         (_, Family::Firefox) => "firefox",
         _ => "chromium",
      }
   }

   /// Stable text form used to group census observations, such as
   /// `chrome/153/linux`.
   #[must_use]
   pub fn key(&self) -> String {
      format!("{}/{}/{}", self.family, self.major, self.platform)
   }
}

fn product_major(user_agent: &str, product: &str) -> Option<u16> {
   let start = user_agent.find(product)? + product.len();
   let digits: String = user_agent[start..]
      .chars()
      .take_while(char::is_ascii_digit)
      .take(5)
      .collect();
   digits.parse().ok()
}
