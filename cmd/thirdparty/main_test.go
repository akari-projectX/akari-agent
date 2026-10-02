package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"Permission is hereby granted, free of charge, to any person obtaining a copy\nof this software", []string{"MIT"}},
		{"Redistribution and use in source and binary forms, with or\nwithout modification, are permitted ... Neither the name of", []string{"BSD-3-Clause"}},
		{"Redistribution and use in source and binary forms, with or without modification, are permitted provided", []string{"BSD-2-Clause"}},
		{"Apache License\n Version 2.0, January 2004", []string{"Apache-2.0"}},
		{"Mozilla Public License Version 2.0\n== ... GNU Affero General Public License, Version 3.0", []string{"MPL-2.0"}},
		{"under the terms of the GNU General Public License as published by\nthe Free Software Foundation, either version 3 of the License, or\n(at your option) any later version.", []string{"GPL-3.0-or-later"}},
		// The full GPL text alone does not say "or later": not decided automatically.
		{"GNU GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007\n TERMS AND CONDITIONS ... either version 3 of the License, or (at your option) any later version", []string{"GPL-3.0"}},
		{"This software is licensed under the LGPLv3, included below.\nAs a special exception ... a Combined Work that links statically or dynamically to this Library", []string{"LGPL-3.0-only WITH LGPL-3.0-linking-exception"}},
		{"Copyright 2019 Klaus Post. Redistribution and use in source and binary forms, with or without modification, are permitted. Neither the name\n---\nApache License Version 2.0, January 2004", []string{"Apache-2.0", "BSD-3-Clause"}},
		{"Do whatever you want.", nil},
	}
	for _, c := range cases {
		if got := classify([]byte(c.text)); !slices.Equal(got, c.want) {
			t.Errorf("classify(%.40q) = %v, want %v", c.text, got, c.want)
		}
	}
}

func TestReadLicensesFailsClosed(t *testing.T) {
	dir := t.TempDir()
	m := &module{Path: "example.com/m", Dir: dir}
	if err := m.readLicenses(); err == nil {
		t.Fatal("module without a licence file accepted")
	}
	os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("All rights reserved."), 0o644)
	if err := m.readLicenses(); err == nil {
		t.Fatal("unrecognised licence accepted")
	}
	m.Files = nil
	os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007 TERMS AND CONDITIONS"), 0o644)
	if err := m.readLicenses(); err == nil {
		t.Fatal("GPL text of unknown version accepted")
	}
	m.Files = nil
	os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("Permission is hereby granted, free of charge, to any person obtaining a copy"), 0o644)
	os.WriteFile(filepath.Join(dir, "NOTICE"), []byte("notice"), 0o644)
	if err := m.readLicenses(); err != nil || m.License != "MIT" || len(m.Files) != 2 {
		t.Fatalf("readLicenses = %v, license %q, files %d", err, m.License, len(m.Files))
	}
}
