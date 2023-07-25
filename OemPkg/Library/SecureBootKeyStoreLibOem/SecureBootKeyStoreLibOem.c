/** @file PlatformKeyLib.c

  Copyright (C) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <UefiSecureBoot.h>

#include <Pi/PiFirmwareFile.h>

#include <Guid/ImageAuthentication.h>

#include <Library/SecureBootVariableLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>

#define PLATFORM_SECURE_BOOT_KEY_COUNT  2

SECURE_BOOT_PAYLOAD_INFO  *gSecureBootPayload     = NULL;
UINT8                     gSecureBootPayloadCount = 0;

UINT8                     mSecureBootPayloadCount                            = PLATFORM_SECURE_BOOT_KEY_COUNT;
SECURE_BOOT_PAYLOAD_INFO  mSecureBootPayload[PLATFORM_SECURE_BOOT_KEY_COUNT] = {
  {
    .SecureBootKeyName = L"Microsoft Only",
    .KekPtr            = NULL,
    .KekSize           = 0,
    .DbPtr             = NULL,
    .DbSize            = 0,
    .DbxPtr            = NULL,
    .DbxSize           = 0,
    .DbtPtr            = NULL,
    .DbtSize           = 0,
  },
  {
    .SecureBootKeyName = L"Microsoft Plus 3rd Party",
    .KekPtr            = NULL,
    .KekSize           = 0,
    .DbPtr             = NULL,
    .DbSize            = 0,
    .DbxPtr            = NULL,
    .DbxSize           = 0,
    .DbtPtr            = NULL,
    .DbtSize           = 0,
  }
};

/**
  Interface to fetch platform Secure Boot Certificates, each payload
  corresponds to a designated set of db, dbx, dbt, KEK, PK.

  @param[in]  Keys        Pointer to hold the returned sets of keys. The
                          returned buffer will be treated as CONST and
                          permanent pointer. The consumer will NOT free
                          the buffer after use.
  @param[in]  KeyCount    The number of sets available in the returned Keys.

  @retval     EFI_SUCCESS             The Keys are properly fetched.
  @retval     EFI_INVALID_PARAMETER   Inputs have NULL pointers.
  @retval     Others                  Something went wrong. Investigate further.
**/
EFI_STATUS
EFIAPI
GetPlatformKeyStore (
  OUT SECURE_BOOT_PAYLOAD_INFO  **Keys,
  OUT UINT8                     *KeyCount
  )
{
  if ((Keys == NULL) || (KeyCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Keys     = gSecureBootPayload;
  *KeyCount = gSecureBootPayloadCount;

  return EFI_SUCCESS;
}

/**
  The constructor gets the secure boot platform keys populated.

  @retval EFI_SUCCESS     The constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
SecureBootKeyStoreLibConstructor (
  VOID
  )
{
  EFI_STATUS                    Status;
  UINTN                         DataSize;
  UINT8                         *Buffer      = NULL;
  UINTN                         BufferSize   = 0;
  EFI_SIGNATURE_LIST            *SigListBuffer   = NULL;
  SECURE_BOOT_CERTIFICATE_INFO  TempInfo;         

  //
  // Retrieve the KeK and associate it.
  //
  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBootKekBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&Buffer,
    &BufferSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate Kek Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }
  mSecureBootPayload[0].KekPtr = Buffer;
  mSecureBootPayload[0].KekSize = BufferSize;
  mSecureBootPayload[1].KekPtr = Buffer;
  mSecureBootPayload[1].KekSize = BufferSize;

  //
  // Retrieve the Db and associate it.
  //
  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBootDbBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&Buffer,
    &BufferSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate Db Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }
  mSecureBootPayload[0].DbPtr = Buffer;
  mSecureBootPayload[0].DbSize = BufferSize;

  //
  // Retrieve the 3rd Party Db and associate it.
  //
  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBoot3PDbBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&Buffer,
    &BufferSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate 3P Db Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }
  mSecureBootPayload[1].DbPtr = Buffer;
  mSecureBootPayload[1].DbSize = BufferSize;

  //
  // Retrieve the Dbx and associate it
  //
  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBootDbxBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&Buffer,
    &BufferSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate Dbx Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }
  mSecureBootPayload[0].DbxPtr = Buffer;
  mSecureBootPayload[0].DbxSize = BufferSize;
  mSecureBootPayload[1].DbxPtr = Buffer;
  mSecureBootPayload[1].DbxSize = BufferSize;

  //
  // Retrieve the Pk and associate it
  //
  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBootPkBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&Buffer,
    &BufferSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate Pk Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }

  TempInfo = (SECURE_BOOT_CERTIFICATE_INFO) {
    .Data     = Buffer,
    .DataSize = BufferSize
  };
  Status = SecureBootCreateDataFromInput (&DataSize, &SigListBuffer, 1, &TempInfo);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to build PK payload!\n", __FUNCTION__));
    ASSERT (FALSE);
  }
  mSecureBootPayload[0].PkPtr = SigListBuffer;
  mSecureBootPayload[0].PkSize = DataSize;
  mSecureBootPayload[1].PkPtr = SigListBuffer;
  mSecureBootPayload[1].PkSize = DataSize;

  // Point the global variable to the static module level payload.
  gSecureBootPayload      = mSecureBootPayload;
  gSecureBootPayloadCount = mSecureBootPayloadCount;

  return EFI_SUCCESS;
}

/**
  Destructor of SecureBootKeyStoreLib, to free any allocated resources.

  @retval EFI_SUCCESS   The destructor completed successfully.
  @retval Other value   The destructor did not complete successfully.

**/
EFI_STATUS
EFIAPI
SecureBootKeyStoreLibDestructor (
  VOID
  )
{
  VOID  *Buffer;

  // This should be initialized from constructor, so casting here is fine
  Buffer = (VOID *)mSecureBootPayload[0].PkPtr;
  if (Buffer != NULL) {
    FreePool (Buffer);
  }

  // Free the Kek allocated by GetSectionFromAnyFv
  Buffer = (VOID *)mSecureBootPayload[0].KekPtr;
  if (Buffer != NULL) {
    FreePool (Buffer);
  }

  // Free the Db allocated by GetSectionFromAnyFv
  Buffer = (VOID *)mSecureBootPayload[0].DbPtr;
  if (Buffer != NULL) {
    FreePool (Buffer);
  }

  // Free the 3P Db allocated by GetSectionFromAnyFv
  Buffer = (VOID *)mSecureBootPayload[1].DbPtr;
  if (Buffer != NULL) {
    FreePool (Buffer);
  }

  // Free the Dbx allocated by GetSectionFromAnyFv
  Buffer = (VOID *)mSecureBootPayload[0].DbxPtr;
  if (Buffer != NULL) {
    FreePool (Buffer);
  }

  return EFI_SUCCESS;
}
