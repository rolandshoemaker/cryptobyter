// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/types"
	"log"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
)

type hpkeKEMID uint16
type hpkeKDFID uint16
type hpkeAEADID uint16

type hpkeCiphersuite struct {
	kdfID  uint16
	aeadID uint16
}

type hpkeKeyConfig struct {
	configID     uint8
	kemID        uint16
	publicKey    []byte            `tls:"uint16prefixed"`
	ciphersuites []hpkeCiphersuite `tls:"uint16prefixed"`
}

type tlsFieldType int

const (
	tlsUint8 tlsFieldType = iota
	tlsUint16
	tlsUint24
	tlsUint32
	tlsUint48
	tlsUint64
	tlsBytes
	tlsSlice
)

type field struct {
	name string

	lengthPrefix int // uint size of length prefix

	typ tlsFieldType

	// if typ is tlsSlice elemName is the name of the element type, and fields
	// are the struct fields for the elements of the slice element type
	elemName string
	fields   []field
}

type parser struct {
	typeName string
	fields   []field
}

const parserPreamble = `func %sParser(input []byte) (*%s, error) {
	var output %s
	s := cryptobyte.String(input)
`

const parserPostamble = `	return &output, nil
}`

func generateFromFields(fields []field, buf *bytes.Buffer, inputName, outputName string) {
	for _, field := range fields {
		switch field.typ {
		case tlsUint8:
			fmt.Fprintf(buf, "if !%s.ReadUint8(&%s.%s) {\nreturn nil, errors.New(\"malformed\")\n}\n", inputName, outputName, field.name)
		case tlsUint16:
			fmt.Fprintf(buf, "if !%s.ReadUint16(&%s.%s) {\nreturn nil, errors.New(\"malformed\")\n}\n", inputName, outputName, field.name)
		case tlsUint32:
			fmt.Fprintf(buf, "if !%s.ReadUint32(&%s.%s) {\nreturn nil, errors.New(\"malformed\")\n}\n", inputName, outputName, field.name)
		case tlsUint64:
			fmt.Fprintf(buf, "if !%s.ReadUint64(&%s.%s) {\nreturn nil, errors.New(\"malformed\")\n}\n", inputName, outputName, field.name)
		case tlsBytes:
			fmt.Fprintf(buf, "if !%s.ReadUint%dLengthPrefixed((*cryptobyte.String)(&%s.%s)) {\nreturn nil, errors.New(\"malformed\")\n}\n", inputName, field.lengthPrefix, outputName, field.name)
		case tlsSlice:
			fmt.Fprintf(buf, "var %s cryptobyte.String\nif !%s.ReadUint%dLengthPrefixed(&%s) {\nreturn nil, errors.New(\"malformed\")\n}\nfor !%s.Empty() {\nvar single_%s %s\n", field.name, inputName, field.lengthPrefix, field.name, field.name, field.name, field.elemName)
			generateFromFields(field.fields, buf, field.name, "single_"+field.name)
			fmt.Fprintf(buf, "%s.%s = append(%s.%s, single_%s)\n}\n", outputName, field.name, outputName, field.name, field.name)
		default:
			log.Fatal("unsupported?")
		}
	}
}

func (p *parser) generate() []byte {
	buf := bytes.NewBuffer(nil)
	// maybe use a template for simplicity
	fmt.Fprintf(buf, parserPreamble, p.typeName, p.typeName, p.typeName)
	generateFromFields(p.fields, buf, "s", "output")
	fmt.Fprint(buf, parserPostamble)
	fmtd, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("code invalid: %s", err)
	}
	return fmtd
}

// basicToFieldType takes a types.Basic type and returns the associated tls field type.
// It should understand how to take field tags into account for non-standard tls sizes.
func basicToFieldType(t types.Type) tlsFieldType {
	switch t.(*types.Basic).Kind() {
	case types.Uint8:
		return tlsUint8
	case types.Uint16:
		return tlsUint16
	case types.Uint32:
		return tlsUint32
	case types.Uint64:
		return tlsUint64
	default:
		log.Fatalf("unsupported basic type: %s", t.(*types.Basic).Name())
	}
	return -1 // unreachable
}

func unwrapNamed(t types.Type) types.Type {
	t = types.Unalias(t)
	named, ok := t.(*types.Named)
	if !ok {
		return t
	}
	return named.Underlying()
}

func parseStructTag(tag string) []string {
	tags := strings.Split(tag, " ")
	for _, f := range tags {
		if !strings.HasPrefix(f, "tls:\"") {
			continue
		}
		f = strings.TrimPrefix(f, "tls:\"")
		f = strings.TrimSuffix(f, "\"")
		return strings.Split(f, ",")
	}
	return nil
}

func getLengthPrefixTag(tag string) int {
	tags := parseStructTag(tag)
	for _, t := range tags {
		switch t {
		case "uint8prefixed":
			return 8
		case "uint16prefixed":
			return 16
		case "uint24prefixed":
			return 24
		}
	}
	return 0
}

func structFields(s *types.Struct) []field {
	var fields []field
	var i int
	for f := range s.Fields() {
		typeField := field{name: f.Name(), typ: -1}

		fieldType := unwrapNamed(f.Type())
		switch t := fieldType.(type) {
		case *types.Basic:
			typeField.typ = basicToFieldType(t)
		case *types.Struct:
			log.Fatal("???")
		case *types.Slice:
			switch et := t.Elem().Underlying().(type) {
			case *types.Basic:
				if et.Kind() != types.Byte {
					log.Fatalf("unsupported slice element type: %s", t.Elem().String())
				}
				typeField.typ = tlsBytes
				lengthPrefix := getLengthPrefixTag(s.Tag(i))
				if lengthPrefix == 0 {
					log.Fatalf("%s is missing a length prefix tag", typeField.name)
				}
				typeField.lengthPrefix = lengthPrefix
			case *types.Struct:
				typeField.typ = tlsSlice
				namedElem, ok := t.Elem().(*types.Named)
				if !ok {
					log.Fatal("anonymous slice elements are not supported")
				}
				typeField.elemName = namedElem.Obj().Name()
				lengthPrefix := getLengthPrefixTag(s.Tag(i))
				if lengthPrefix == 0 {
					log.Fatalf("%s is missing a length prefix tag", typeField.name)
				}
				typeField.lengthPrefix = lengthPrefix
				typeField.fields = structFields(et)
			default:
				log.Fatalf("unsupported slice element type: %s", t.Elem().String())
			}
		}

		fields = append(fields, typeField)
		i++
	}
	return fields
}

func main() {
	ts := []string{"hpkeKeyConfig"}
	patterns := []string{"."}
	tags := []string{}

	cfg := &packages.Config{
		Mode:       packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedFiles,
		Tests:      true,
		BuildFlags: []string{fmt.Sprintf("-tags=%s", strings.Join(tags, " "))},
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		log.Fatal(err)
	}
	if len(pkgs) == 0 {
		log.Fatalf("error: no packages matching %v", strings.Join(patterns, " "))
	}

	for _, pkg := range pkgs {
		for ident, def := range pkg.TypesInfo.Defs {
			if !slices.Contains(ts, ident.Name) {
				continue
			}
			if _, ok := def.Type().(*types.Named); !ok {
				log.Fatal("bad type")
			}
			s, ok := def.Type().Underlying().(*types.Struct)
			if !ok {
				log.Fatal("bad type")
			}

			p := parser{typeName: ident.Name}
			p.fields = structFields(s)

			fmt.Println(string(p.generate()))
		}
	}
}
