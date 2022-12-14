//! Some helper macros for the crate
//! 
/// Shorthand for implementing serialization functionality for a type
#[macro_export]
macro_rules! serializable {
    ($($id:ident),+) => {
        $(
            // Implement
            #[pymethods]
            impl $id {
                #[new]
                fn __init__(value: String) -> PyResult<Self> {
                    match serde_json::from_str(&value) {
                        // Match statements måste täcka alla tänkbara fall, i detta fall ok eller error
                        Ok(value) => Ok(value),
                        Err(e) => {
                            return Err(PyErr::new::<PyValueError, _>(format!("{}",e)));
                        }
                    }
                }

                fn __str__(&self) -> PyResult<String> {
                    match serde_json::to_string(&self) {
                        Ok(value) => Ok(value),
                        Err(e) => {
                            return Err(PyErr::new::<PyValueError, _>(format!("{}", e)));
                        }
                    }
                }
            }
        )+
    };
}
/// Shorthand for adding a bunch of functions to a python module
#[macro_export]
macro_rules! add_functions {
    ($m:ident;$($function:ident),+) => {
      $(
        $m.add_function(wrap_pyfunction!($function, $m)?)?;
      )+
    };
}
/// Shorthand for adding a bunch of types to a python module
#[macro_export]
macro_rules! add_types {
    ($m:ident;$($t:ident),+) => {
      $(
        $m.add_class::<$t>()?;
      )+
    };
}