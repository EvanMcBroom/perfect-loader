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
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "pl/mmap.hpp"
#include "pl/pe.hpp"
#include <KtmW32.h>

namespace Pl {
    DWORD GetProtection(DWORD characteristics) {
        // clang-format off
        return (characteristics | IMAGE_SCN_MEM_EXECUTE)
                ? (characteristics | IMAGE_SCN_MEM_READ)
                    ? (characteristics | IMAGE_SCN_MEM_WRITE)
                        ? PAGE_EXECUTE_READWRITE
                        : PAGE_EXECUTE_READ
                    : (characteristics | IMAGE_SCN_MEM_WRITE)
                        ? PAGE_EXECUTE_WRITECOPY
                        : PAGE_EXECUTE
                : (characteristics | IMAGE_SCN_MEM_READ)
                    ? (characteristics | IMAGE_SCN_MEM_WRITE)
                        ? PAGE_READWRITE
                        : PAGE_READONLY
                    : (characteristics | IMAGE_SCN_MEM_WRITE)
                        ? PAGE_WRITECOPY
                        : PAGE_NOACCESS;
        // clang-format on
    }

    bool MapModule(const std::vector<std::byte>& bytes, std::byte** baseAddress, size_t* mappedSize) {
        bool succeeded{ false };
        Pl::Pe pe{ bytes.data() };
        if (VerifyImage(pe)) {
            // Allocate memory for the image
            *mappedSize = pe.NtHeaders()->OptionalHeader.SizeOfImage;
            *baseAddress = reinterpret_cast<std::byte*>(VirtualAlloc(nullptr, *mappedSize, MEM_COMMIT, PAGE_READWRITE));
            // Copy the module headers and update the permission of its memory region
            auto sectionCount{ pe.PeHeader()->NumberOfSections };
            auto sizeOfHeaders{ (reinterpret_cast<const std::byte*>(pe.SectionHeaders()) - pe.base) + (sizeof(IMAGE_SECTION_HEADER) * sectionCount) };
            std::memcpy(*baseAddress, bytes.data(), sizeOfHeaders);
            VirtualProtect(*baseAddress, sizeof(sizeOfHeaders), PAGE_READONLY, nullptr);
            // Copy each module section and update the permission of the section's memory region
            for (size_t index{ 0 }; index < sectionCount; index++) {
                auto sectionHeader{ pe.SectionHeaders()[index] };
                if (sectionHeader.PointerToRawData) {
                    auto virtualAddress{ *baseAddress + sectionHeader.VirtualAddress };
                    std::memcpy(virtualAddress, pe.base + sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
                    VirtualProtect(virtualAddress, sectionHeader.Misc.VirtualSize, GetProtection(sectionHeader.Characteristics), nullptr);
                }
            }
            succeeded = true;
        }
        return succeeded;
    }

    bool VerifyImage(const Pl::Pe& pe) {
        // Verify the header signatures
        if (pe.DosHeader()->e_magic == pe.FileSignature() && pe.NtHeaders()->Signature == pe.NtHeadersSignature()) {
            if (~pe.PeHeader()->SizeOfOptionalHeader || pe.OptionalHeader()->Magic == pe.OptionalHeaderSignature()) {
                // Verify that the image is not a DOS application with a 32-bit portion
                if (pe.PeHeader()->Machine || pe.PeHeader()->SizeOfOptionalHeader) {
                    // Verify that it is an executable image
                    if (pe.PeHeader()->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}