// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package safeelf provides panic-safe wrappers around debug/elf.
//
// Go's debug/elf is not hardened against adversarial inputs and may panic on
// malformed data. Since Inspektor Gadget parses ELF files from untrusted
// containers in a privileged process, we wrap all operations in recover() to
// turn panics into errors.
//
// This approach is inspired by cilium/ebpf's internal SafeELFFile:
// https://github.com/cilium/ebpf/blob/main/internal/elf.go
package safeelf

import (
	"debug/elf"
	"fmt"
	"io"
)

// MaxSymbolTableSize is the maximum combined size of a symbol table section
// and its associated string table that Symbols and DynamicSymbols will read.
// ELF files coming from containers are untrusted and debug/elf reads those
// sections entirely in memory, so without this limit a large binary could
// make the privileged Inspektor Gadget process allocate as much memory.
// 64 MiB is generous: the symbol and string tables of large Go binaries such
// as dockerd or ig are below 16 MiB.
const MaxSymbolTableSize = 64 * 1024 * 1024

// File wraps an *elf.File with panic recovery on operations that may crash
// on malformed input.
type File struct {
	*elf.File
}

// checkSymbolTableSize returns an error if the given symbol table section, or
// the string table it refers to, is bigger than MaxSymbolTableSize.
func (f *File) checkSymbolTableSize(sectionType elf.SectionType) error {
	symbols := f.SectionByType(sectionType)
	if symbols == nil {
		// Let debug/elf report the missing section.
		return nil
	}

	size := symbols.Size
	if int(symbols.Link) < len(f.Sections) {
		strings := f.Sections[symbols.Link]
		if strings.Size > ^uint64(0)-size {
			return fmt.Errorf("%s size overflow", symbols.Name)
		}
		size += strings.Size
	}

	if size > MaxSymbolTableSize {
		return fmt.Errorf("%s too large (%d bytes with its string table, max %d)",
			symbols.Name, size, MaxSymbolTableSize)
	}

	return nil
}

// NewFile reads an ELF file safely. Any panic during parsing is turned into
// an error.
func NewFile(r io.ReaderAt) (safe *File, err error) {
	defer func() {
		if r := recover(); r != nil {
			safe = nil
			err = fmt.Errorf("panic reading ELF file: %v", r)
		}
	}()

	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	return &File{f}, nil
}

// Symbols is the safe version of elf.File.Symbols.
func (f *File) Symbols() (syms []elf.Symbol, err error) {
	defer func() {
		if r := recover(); r != nil {
			syms = nil
			err = fmt.Errorf("panic reading ELF symbols: %v", r)
		}
	}()

	if err := f.checkSymbolTableSize(elf.SHT_SYMTAB); err != nil {
		return nil, err
	}

	return f.File.Symbols()
}

// DynamicSymbols is the safe version of elf.File.DynamicSymbols.
func (f *File) DynamicSymbols() (syms []elf.Symbol, err error) {
	defer func() {
		if r := recover(); r != nil {
			syms = nil
			err = fmt.Errorf("panic reading ELF dynamic symbols: %v", r)
		}
	}()

	if err := f.checkSymbolTableSize(elf.SHT_DYNSYM); err != nil {
		return nil, err
	}

	return f.File.DynamicSymbols()
}
