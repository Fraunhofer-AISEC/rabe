use pyo3::{ prelude::*, wrap_pymodule };

mod macros;
mod lsw;



/// A Python module implemented in Rust.
#[pymodule]
fn rabe_py(_py: Python, m: &PyModule) -> PyResult<()> {

    m.add_wrapped(wrap_pymodule!(lsw::lsw))?;

    Ok(())
}