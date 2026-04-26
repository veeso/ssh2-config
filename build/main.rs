#[cfg(feature = "reload-ssh-algo")]
mod define_parser;
#[cfg(feature = "reload-ssh-algo")]
mod openssh;
#[cfg(feature = "reload-ssh-algo")]
mod src_writer;

#[cfg(feature = "reload-ssh-algo")]
fn main() -> anyhow::Result<()> {
    let prefs = openssh::get_my_prefs()?;
    src_writer::write_source(prefs)?;

    Ok(())
}

#[cfg(not(feature = "reload-ssh-algo"))]
fn main() {}
