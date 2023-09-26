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

#pragma once
#include "pe.hpp"
#include <vector>

namespace Pl {
    /// <summary>
    /// Gets an appropriate page protection value for an executable image section.
    /// </summary>
    /// <param name="characteristics">The characteristics on an executable image section.</param>
    /// <returns>The determined page protection value.</returns>
    DWORD GetProtection(DWORD characteristics);

    /// <summary>
    /// Maps the provided module bytes as an executable image in the address space of the calling process.
    /// </summary>
    /// <param name='bytes'>The bytes of the module to map.</param>
    /// <param name='baseAddress'>Pointer to a variable that receives the base address of the mapped module.</param>
    /// <param name='mappedSize'>Pointer to a variable that receives the final size of the mapped module.</param>
    /// <returns>Returns a bool value to indicate if the module was successfully mapped.</returns>
    bool MapModule(const std::vector<std::byte>& bytes, std::byte** baseAddress, size_t* mappedSize);
    
    /// <summary>
    /// Verify that an executable image conforms to the PE file format.
    /// </summary>
    /// <param name="pe">The executable image to verify.</param>
    /// <returns>If the executable image conforming.</returns>
    /// <remarks>
    /// The image does not need to be mapped to be verified.
    /// No verification will be performed for the alignment of an image's internal data structures or the alignment of their values.
    /// </remarks>
    bool VerifyImage(const Pl::Pe& pe);
}