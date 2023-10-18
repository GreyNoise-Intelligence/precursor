use indicatif::{ProgressBar, ProgressStyle};

pub fn create_progress_bar(size: u64, quiet: bool) -> ProgressBar {
    if !quiet {
        let style = ProgressStyle::default_bar()
            .template("[{elapsed_precise} {eta}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap();
        ProgressBar::new(size).with_style(style)
    } else {
        ProgressBar::hidden()
    }
}
