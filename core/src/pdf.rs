//! Removes identifying metadata from outgoing PDF documents.

use lopdf::{Dictionary, Document, Object, ObjectId};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PdfError {
    #[error("pdf parse: {0}")]
    Parse(String),
    #[error("pdf is encrypted; refusing to rewrite it")]
    Encrypted,
    #[error("pdf write: {0}")]
    Write(String),
}

const METADATA_KEYS: [&[u8]; 2] = [b"Metadata", b"PieceInfo"];

#[uniffi::export]
pub fn pdf_strip_metadata(data: Vec<u8>) -> Result<Vec<u8>, PdfError> {
    let mut doc = Document::load_mem(&data).map_err(|e| PdfError::Parse(e.to_string()))?;

    if doc.trailer.get(b"Encrypt").is_ok() {
        return Err(PdfError::Encrypted);
    }

    if let Ok(Object::Reference(id)) = doc.trailer.get(b"Info").cloned() {
        blank_object(&mut doc, id);
    }
    doc.trailer.remove(b"Info");

    let catalog_id = doc
        .catalog()
        .ok()
        .and_then(|_| doc.trailer.get(b"Root").ok().cloned())
        .and_then(|root| match root {
            Object::Reference(id) => Some(id),
            _ => None,
        });
    if let Some(id) = catalog_id {
        strip_keys_from(&mut doc, id);
    }

    let page_ids: Vec<ObjectId> = doc.page_iter().collect();
    for id in page_ids {
        strip_keys_from(&mut doc, id);
    }

    doc.trailer.remove(b"ID");

    doc.prune_objects();
    doc.renumber_objects();

    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| PdfError::Write(e.to_string()))?;
    Ok(out)
}

fn blank_object(doc: &mut Document, id: ObjectId) {
    if let Some(obj) = doc.objects.get_mut(&id) {
        *obj = Object::Dictionary(Dictionary::new());
    }
}

fn strip_keys_from(doc: &mut Document, id: ObjectId) {
    let mut referenced = Vec::new();
    if let Some(Object::Dictionary(dict)) = doc.objects.get_mut(&id) {
        for key in METADATA_KEYS {
            if let Ok(Object::Reference(rid)) = dict.get(key) {
                referenced.push(*rid);
            }
            dict.remove(key);
        }
    }
    for rid in referenced {
        blank_object(doc, rid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Stream};

    fn document_with_metadata() -> (Vec<u8>, &'static str) {
        let mut doc = Document::with_version("1.5");

        let content_bytes = b"BT /F1 12 Tf 72 720 Td (Hello from the document body) Tj ET";
        let content_id = doc.add_object(Stream::new(dictionary! {}, content_bytes.to_vec()));

        let catalog_xmp = doc.add_object(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            b"<x:xmpmeta><dc:creator>Jane Author</dc:creator></x:xmpmeta>".to_vec(),
        ));
        let page_xmp = doc.add_object(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            b"<x:xmpmeta><pdf:Producer>Secret Editor 9</pdf:Producer></x:xmpmeta>".to_vec(),
        ));

        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Metadata" => page_xmp,
            "PieceInfo" => dictionary! { "SomeEditor" => dictionary! { "Private" => "/Users/jane/secret/path.pdf" } },
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Count" => 1, "Kids" => vec![page_id.into()],
            }),
        );

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id, "Metadata" => catalog_xmp,
        });
        let info_id = doc.add_object(dictionary! {
            "Author" => Object::string_literal("Jane Author"),
            "Producer" => Object::string_literal("Secret Editor 9"),
            "Creator" => Object::string_literal("/Users/jane/secret/path.pdf"),
        });

        doc.trailer.set("Root", catalog_id);
        doc.trailer.set("Info", info_id);
        doc.trailer.set(
            "ID",
            Object::Array(vec![
                Object::string_literal("stable-doc-identity"),
                Object::string_literal("stable-doc-identity"),
            ]),
        );

        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).expect("build fixture");
        (bytes, "Hello from the document body")
    }

    fn as_text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }

    #[test]
    fn strips_every_identifying_field() {
        let (input, body) = document_with_metadata();

        let before = as_text(&input);
        assert!(before.contains("Jane Author"), "fixture lacks an author");
        assert!(before.contains("Secret Editor 9"), "fixture lacks a producer");
        assert!(before.contains("/Users/jane/secret"), "fixture lacks a path");
        assert!(before.contains("stable-doc-identity"), "fixture lacks a doc id");

        let cleaned = pdf_strip_metadata(input).expect("strip");
        let after = as_text(&cleaned);

        assert!(!after.contains("Jane Author"), "author survived");
        assert!(!after.contains("Secret Editor 9"), "producer survived");
        assert!(!after.contains("/Users/jane/secret"), "local path survived");
        assert!(!after.contains("stable-doc-identity"), "document id survived");
        assert!(!after.contains("xmpmeta"), "XMP packet survived");

        assert!(after.contains(body), "page content was damaged");
    }

    #[test]
    fn cleaned_document_still_parses_and_keeps_its_pages() {
        let (input, _) = document_with_metadata();
        let cleaned = pdf_strip_metadata(input).expect("strip");

        let doc = Document::load_mem(&cleaned).expect("cleaned pdf must still parse");
        assert_eq!(doc.page_iter().count(), 1, "page count changed");
        assert!(doc.trailer.get(b"Info").is_err(), "Info is still referenced");
        assert!(doc.trailer.get(b"ID").is_err(), "ID is still present");
    }

    #[test]
    fn stripping_twice_is_stable() {
        let (input, body) = document_with_metadata();
        let once = pdf_strip_metadata(input).expect("first");
        let twice = pdf_strip_metadata(once.clone()).expect("second");
        assert!(as_text(&twice).contains(body), "content lost on second pass");
        assert!(Document::load_mem(&twice).is_ok(), "second pass corrupted it");
    }

    #[test]
    fn garbage_input_fails_closed() {
        assert!(pdf_strip_metadata(b"not a pdf at all".to_vec()).is_err());
        assert!(pdf_strip_metadata(Vec::new()).is_err());
    }

    #[test]
    fn encrypted_documents_are_refused_not_mangled() {
        let (input, _) = document_with_metadata();
        let mut doc = Document::load_mem(&input).unwrap();
        let enc = doc.add_object(dictionary! { "Filter" => "Standard", "V" => 1 });
        doc.trailer.set("Encrypt", enc);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();

        match pdf_strip_metadata(bytes) {
            Err(PdfError::Encrypted) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
