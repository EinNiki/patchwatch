//! Docker-Container und Image-Versionen: Annahme der Agent-Meldung, Registry-Prüfung und Auswertung.
//! Es wird nie ein Image gezogen oder ein Container verändert; alles hier ist reine Anzeige.
pub mod announce;
pub mod eval;
pub mod intake;
pub mod reference;
pub mod registry;
pub mod tags;
pub mod view;
pub mod worker;
