// AUDIT C-7 (documents) — strip identifying metadata from an outgoing PDF.
//
// Images are re-encoded and videos are remuxed before they leave the device, so the
// EXIF GPS fix and the QuickTime location atom never ride along inside the encrypted
// attachment. Documents were the hole left in that story: a PDF carries the author's
// name, the producing application and often the full local file path in its Info
// dictionary and its XMP packet, and none of it was touched. Sending one deanonymized
// the sender to the recipient as effectively as a geotag would.
//
// This lives in the shared Rust core rather than in each platform's media pipeline
// because neither Android nor iOS ships a PDF *writer* — Android has no such API at
// all, and PDFKit cannot rewrite a document's metadata in place without re-rendering
// it. One implementation here also means the two platforms cannot drift into stripping
// different fields.
//
// SCOPE, honestly: this removes DOCUMENT-level metadata — the Info dictionary, the XMP
// packet, page-level XMP, and the private per-application blobs (PieceInfo) that
// editors leave behind. It does NOT rewrite content streams, so text that a human
// typed into the document (a letterhead, a signature block) stays, exactly as the
// pixels of a photo stay after EXIF is stripped. It also cannot help with an encrypted
// PDF, which is refused rather than silently passed through.
//
// The input here is a file the USER picked to send, not a hostile document, so the
// parser is not sitting on an attack surface. It is still wrapped in error handling
// rather than unwraps: a PDF that lopdf cannot parse must fail the send (fail-closed,
// same as the image and video paths) instead of falling back to the original.

use lopdf::{Dictionary, Document, Object, ObjectId};

/// Errors surfaced across the FFI when a PDF cannot be cleaned.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PdfError {
    #[error("pdf parse: {0}")]
    Parse(String),
    #[error("pdf is encrypted; refusing to rewrite it")]
    Encrypted,
    #[error("pdf write: {0}")]
    Write(String),
}

/// Keys removed from the document catalog and from each page.
const METADATA_KEYS: [&[u8]; 2] = [b"Metadata", b"PieceInfo"];

/// Strips document metadata from [data] and returns the rewritten PDF.
///
/// Fail-closed by contract: every failure is an error, never the original bytes, so a
/// caller cannot accidentally send an uncleaned document because a rewrite went wrong.
#[uniffi::export]
pub fn pdf_strip_metadata(data: Vec<u8>) -> Result<Vec<u8>, PdfError> {
    let mut doc = Document::load_mem(&data).map_err(|e| PdfError::Parse(e.to_string()))?;

    // An encrypted document cannot be rewritten without its password, and saving one
    // half-decrypted would corrupt it. Refuse instead of guessing.
    if doc.trailer.get(b"Encrypt").is_ok() {
        return Err(PdfError::Encrypted);
    }

    // 1. The Info dictionary — Author, Creator, Producer, Title, Subject, Keywords and
    //    the creation/modification timestamps. Detach it from the trailer AND blank the
    //    object it pointed at, since the object itself survives in the file otherwise.
    if let Ok(Object::Reference(id)) = doc.trailer.get(b"Info").cloned() {
        blank_object(&mut doc, id);
    }
    doc.trailer.remove(b"Info");

    // 2. The catalog's XMP packet (an XML stream that repeats the Info fields and adds
    //    document/instance ids that link separately-sent copies to one another) and the
    //    PieceInfo blobs editors use to stash private application state.
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

    // 3. Pages carry their own optional XMP and PieceInfo.
    let page_ids: Vec<ObjectId> = doc.page_iter().collect();
    for id in page_ids {
        strip_keys_from(&mut doc, id);
    }

    // 4. The trailer's /ID pair is a document identity that persists across saves and
    //    links copies of the same file. Regenerating is not enough — it must simply go.
    doc.trailer.remove(b"ID");

    // Drop the objects nothing points at any more (the old Info dictionary, orphaned
    // XMP streams) so they cannot be recovered from the file's free space, then
    // renumber so no dangling generation survives.
    doc.prune_objects();
    doc.renumber_objects();

    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| PdfError::Write(e.to_string()))?;
    Ok(out)
}

/// Replaces an object with an empty dictionary. Removing the entry alone would leave
/// the metadata sitting in the file, reachable by anyone reading the raw bytes.
fn blank_object(doc: &mut Document, id: ObjectId) {
    if let Some(obj) = doc.objects.get_mut(&id) {
        *obj = Object::Dictionary(Dictionary::new());
    }
}

/// Removes the metadata keys from the dictionary at [id], blanking whatever they
/// referenced so the stream does not merely become unreferenced.
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

    /// Builds a one-page PDF carrying every metadata surface this module strips: an
    /// Info dictionary, a catalog XMP packet, a page-level XMP packet, PieceInfo, and
    /// a trailer /ID — plus real page content that must survive untouched.
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
        // The fixture must actually contain what we claim to remove, or this test
        // would pass against a document that never had metadata in the first place.
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

        // ...and the document is still the document.
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
        // The send path may run over an already-clean file; that must be a no-op
        // rather than a failure, and must not keep shrinking or corrupting it.
        let (input, body) = document_with_metadata();
        let once = pdf_strip_metadata(input).expect("first");
        let twice = pdf_strip_metadata(once.clone()).expect("second");
        assert!(as_text(&twice).contains(body), "content lost on second pass");
        assert!(Document::load_mem(&twice).is_ok(), "second pass corrupted it");
    }

    #[test]
    fn garbage_input_fails_closed() {
        // Fail-closed is the whole contract: the caller must never be handed back
        // something it could mistake for a cleaned document.
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
