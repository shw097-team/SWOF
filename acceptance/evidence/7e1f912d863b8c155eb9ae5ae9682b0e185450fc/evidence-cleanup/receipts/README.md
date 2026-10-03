# receipts/

This directory deliberately contains NO evidence. Generation-time receipts were removed from
the immutable evidence set because any artifact that DESCRIBES the set is invalidated by the
next regeneration of that set (three instances of that defect class were found: the historical
W1_R4_FINAL_PACKAGING.json, and in-tree E8_FINAL_RECEIPT.json and E6_PACK_RECEIPT.json).

The receipts are preserved verbatim under receipts/superseded/ and are still delivered as
out-of-tree artifacts alongside the readset. The immutable set now contains only the evidence
artifacts themselves plus compiler raw output, each self-contained and hashable.
