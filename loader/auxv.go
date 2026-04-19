package loader

// StandardAuxv builds the AuxEntry list that libc expects to see on
// process entry, given an already-planned Image. The caller supplies
// the interpreter's load bias (zero for a static binary) because
// that information only exists after the interpreter has itself
// been planned — the ELF parser can't know it.
//
// Callers who want to override or add entries (AT_HWCAP, AT_SECURE,
// AT_UID …) should append to the returned slice before handing it
// to BuildStartStack. Tags whose values live in the aux-data region
// (AT_RANDOM / AT_PLATFORM / AT_EXECFN) are NOT included here —
// BuildStartStack appends them itself based on the raw bytes passed
// via BuildInput.
func StandardAuxv(img *Image, interpBase uint64) []AuxEntry {
	aux := []AuxEntry{
		{Type: AtPHDR, Val: img.PhdrAddr},
		{Type: AtPHEnt, Val: img.PhEnt},
		{Type: AtPHNum, Val: img.PhNum},
		{Type: AtPageSz, Val: 4096},
		{Type: AtBase, Val: interpBase},
		{Type: AtFlags, Val: 0},
		{Type: AtEntry, Val: img.Entry},
	}
	return aux
}
