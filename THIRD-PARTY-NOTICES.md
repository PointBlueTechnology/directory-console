# Third-party notices

Directory Console's own code is under its [MIT license](LICENSE). The container image and the web UI built
into it also include the components below. Each keeps its own license, reproduced here as those licenses
require. This file is in the image at `/app/THIRD-PARTY-NOTICES.md`.

No NetIQ/OpenText code is included. Identity Manager is reached through DirXMLDev over JLDAP.

## Summary

| Component | Version | Where | License |
|---|---|---|---|
| JLDAP (`com.novell.ldap:jldap`) | 4.3 | image (`/app/lib`) | OpenLDAP Public License 2.0.1 |
| Bouncy Castle (`bcprov`, `bcpkix`, `bcutil`, `-jdk18on`) | 1.80, 1.80.2 | image (`/app/lib`) | Bouncy Castle Licence (MIT) |
| DirXMLDev (`com.pointblue.dirxml:dirxml-dev`) | see `pom.xml` | image (`/app/lib`) | MIT, Point Blue Technology |
| DirXMLSimulator (`com.pointblue.dirxml:dirxml-simulator`) | see `pom.xml` | image (`/app/lib`) | MIT, Point Blue Technology |
| PatternFly, React and their dependencies | see below | web UI | MIT; `tslib` 0BSD |
| Red Hat Display, Red Hat Text, Red Hat Mono fonts | from PatternFly 6.6.1 | web UI | SIL Open Font License 1.1 |

## JLDAP

Copyright (C) 1999 - 2003 Novell, Inc. All Rights Reserved.

This work is subject to version 2.0.1 of the OpenLDAP Public License. Due credit is given to the OpenLDAP
Project (http://www.openldap.org/).

```
The OpenLDAP Public License
Version 2.0.1, 21 December 1999

Copyright 1999, The OpenLDAP Foundation, Redwood City, California, USA. All Rights Reserved.

Redistribution and use of this software and associated documentation ("Software"), with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain copyright statements and notices. Redistributions must also contain a copy of this document.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. The name "OpenLDAP" must not be used to endorse or promote products derived from this Software without prior written permission of the OpenLDAP Foundation. For written permission, please contact foundation@openldap.org.

4. Products derived from this Software may not be called "OpenLDAP" nor may "OpenLDAP" appear in their names without prior written permission of the OpenLDAP Foundation. OpenLDAP is a trademark of the OpenLDAP Foundation.

5. Due credit should be given to the OpenLDAP Project (http://www.openldap.org/).

THIS SOFTWARE IS PROVIDED BY THE OPENLDAP FOUNDATION AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE OPENLDAP FOUNDATION OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Bouncy Castle

```
Copyright (c) 2000 - 2023 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Web UI: MIT-licensed packages

Each of these packages is under the MIT License, with the copyright notice shown:

| Package | Version | Copyright |
|---|---|---|
| @patternfly/patternfly, react-core, react-icons, react-styles, react-table, react-tokens | 6.6.1 | Copyright (c) 2019 Red Hat, Inc. |
| react, react-dom, scheduler | 19.3.0, 0.28.0 | Copyright (c) Meta Platforms, Inc. and affiliates. |
| prop-types | 15.8.1 | Copyright (c) 2013-present, Facebook, Inc. |
| react-is | 16.13.1 | Copyright (c) Facebook, Inc. and its affiliates. |
| react-dropzone | 14.4.1 | Copyright (c) 2018 Param Aggarwal |
| attr-accept | 2.2.5 | Copyright (c) 2015 Andrey Okonetchnikov |
| file-selector | 2.1.2 | Copyright (c) 2020 Roland Groza |
| focus-trap, tabbable | 7.6.6, 6.5.0 | Copyright (c) 2015-2016 David Clark |
| js-tokens | 4.0.0 | Copyright (c) 2014, 2015, 2016, 2017, 2018 Simon Lydell |
| lodash | 4.18.1 | Copyright OpenJS Foundation and other contributors <https://openjsf.org/> |
| loose-envify | 1.4.0 | Copyright (c) 2015 Andres Suarez <zertosh@gmail.com> |
| object-assign | 4.1.1 | Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (sindresorhus.com) |

The MIT License, as it applies to each package above with its own copyright notice:

```
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Web UI: tslib

`tslib` 2.8.1. Copyright (c) Microsoft Corporation. Licensed under the BSD Zero Clause License (0BSD):

```
Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is
hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## Fonts: Red Hat Display, Red Hat Text, Red Hat Mono

Copyright The Red Hat Project Authors (https://github.com/RedHatOfficial/RedHatFont), distributed with
PatternFly. Licensed under the SIL Open Font License, Version 1.1:

```
SIL OPEN FONT LICENSE

Version 1.1 - 26 February 2007

PREAMBLE

The goals of the Open Font License (OFL) are to stimulate worldwide development of collaborative font projects, to support the font creation efforts of academic and linguistic communities, and to provide a free and open framework in which fonts may be shared and improved in partnership with others.

The OFL allows the licensed fonts to be used, studied, modified and redistributed freely as long as they are not sold by themselves. The fonts, including any derivative works, can be bundled, embedded, redistributed and/or sold with any software provided that any reserved names are not used by derivative works. The fonts and derivatives, however, cannot be released under any other type of license. The requirement for fonts to remain under this license does not apply to any document created using the fonts or their derivatives.

DEFINITIONS

"Font Software" refers to the set of files released by the Copyright Holder(s) under this license and clearly marked as such. This may include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the copyright statement(s).

"Original Version" refers to the collection of Font Software components as distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting, or substituting — in part or in whole — any of the components of the Original Version, by changing formats or by porting the Font Software to a new environment.

"Author" refers to any designer, engineer, programmer, technical writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS

Permission is hereby granted, free of charge, to any person obtaining a copy of the Font Software, to use, study, copy, merge, embed, modify, redistribute, and sell modified and unmodified copies of the Font Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components, in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled, redistributed and/or sold with any software, provided that each copy contains the above copyright notice and this license. These can be included either as stand-alone text files, human-readable headers or in the appropriate machine-readable metadata fields within text or binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font Name(s) unless explicit written permission is granted by the corresponding Copyright Holder. This restriction only applies to the primary font name as presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font Software shall not be used to promote, endorse or advertise any Modified Version, except to acknowledge the contribution(s) of the Copyright Holder(s) and the Author(s) or with their explicit written permission.

5) The Font Software, modified or unmodified, in part or in whole, must be distributed entirely under this license, and must not be distributed under any other license. The requirement for fonts to remain under this license does not apply to any document created using the Font Software.

TERMINATION

This license becomes null and void if any of the above conditions are not met.

DISCLAIMER

THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM OTHER DEALINGS IN THE FONT SOFTWARE.
```
