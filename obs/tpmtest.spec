#
# spec file for package tpmtest
#
# Copyright (c) <2026> Perry Werneck <perry.werneck@gmail.com>.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://github.com/PerryWerneck/tpmtest/issues
#

Summary:		Test application for tpm2tss 
Name:			tpmtest
Version:		0.0.1
Release:		0
License:		LGPL-3.0
Source:			%{name}-%{version}.tar.xz

URL:			https://github.com/PerryWerneck/tpmtest

Group:			Development/Libraries/C and C++
BuildRoot:		/var/tmp/%{name}-%{version}

BuildRequires:	binutils
BuildRequires:	coreutils
BuildRequires:	gcc-c++
BuildRequires:	pkgconfig(libnm)
BuildRequires:	pkgconfig(openssl)
BuildRequires:	meson >= 0.61.4

%description
Simple application for testing tpm2tss and wpa-supplicant

%prep
%autosetup
%meson

%build
%meson_build

%install
%meson_install

%files
%{_bindir}/tpmtest

%changelog

