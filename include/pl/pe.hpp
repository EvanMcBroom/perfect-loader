// Copyright (c) 2023 Evan McBroom
//
// This file is part of perfect-loader.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
#pragma once
#include <cstddef>
#include <winnt.h>

namespace Pl {
    struct Pe {
        const std::byte* base;

        inline Pe(const std::byte* base = nullptr) {
            this->base = (base) ? base : reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
        }

        inline auto DosHeader() const {
            return reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        }

        constexpr auto FileSignature() const {
            return IMAGE_DOS_SIGNATURE;
        }

        inline auto NtHeaders() const {
            return reinterpret_cast<const IMAGE_NT_HEADERS*>(this->base + DosHeader()->e_lfanew);
        }

        constexpr auto NtHeadersSignature() const {
            return IMAGE_NT_SIGNATURE;
        }

        inline auto OptionalHeader() const {
            return &NtHeaders()->OptionalHeader;
        }

        constexpr auto OptionalHeaderSignature() const {
            return IMAGE_NT_OPTIONAL_HDR_MAGIC;
        }

        inline auto PeHeader() const {
            return &NtHeaders()->FileHeader;
        }

        inline auto SectionHeaders() const {
            return reinterpret_cast<const IMAGE_SECTION_HEADER*>(reinterpret_cast<const std::byte*>(OptionalHeader()) + PeHeader()->SizeOfOptionalHeader);
        }
    };
}
