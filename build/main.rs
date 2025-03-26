mod define_parser;
mod openssh;
mod src_writer;

fn main() -> anyhow::Result<()> {
    let prefs = openssh::get_my_prefs()?;
    src_writer::write_source(prefs)?;

    Ok(())
}
