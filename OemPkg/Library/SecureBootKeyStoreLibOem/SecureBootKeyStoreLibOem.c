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

#include "MsSecureBootDefaultVars.h"

#define PLATFORM_SECURE_BOOT_KEY_COUNT  2

SECURE_BOOT_PAYLOAD_INFO  *gSecureBootPayload     = NULL;
UINT8                     gSecureBootPayloadCount = 0;

// Note: This will not work as it will not be accepted as a valid X509 cert
CONST UINT8  mDevelopmentPlatformKeyCertificate[] = { 0 };

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
  UINT8                         *KekDefault      = NULL;
  UINTN                         KekDefaultSize   = 0;
  UINT8                         *DbDefault       = NULL;
  UINTN                         DbDefaultSize    = 0;
  UINT8                         *Db3PDefault     = NULL;
  UINTN                         Db3PDefaultSize  = 0;
  UINT8                         *DbxDefault      = NULL;
  UINTN                         DbxDefaultSize   = 0;
  EFI_SIGNATURE_LIST            *SigListBuffer   = NULL;
  SECURE_BOOT_CERTIFICATE_INFO  TempInfo         = {
    .Data     = mDevelopmentPlatformKeyCertificate,
    .DataSize = sizeof (mDevelopmentPlatformKeyCertificate)
  };

  //
  // First, we must build the PK buffer with the correct data.
  //
  Status = SecureBootCreateDataFromInput (&DataSize, &SigListBuffer, 1, &TempInfo);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to build PK payload!\n", __FUNCTION__));
    ASSERT (FALSE);
  }

  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBootKekBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&KekDefault,
    &KekDefaultSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate Kek Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }

  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBootDbBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&DbDefault,
    &DbDefaultSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate Db Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }

  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBoot3PDbBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&Db3PDefault,
    &Db3PDefaultSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate 3P Db Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }

  Status = GetSectionFromAnyFv(
    PcdGetPtr(PcdSecureBotDbxBinaryFile),
    EFI_SECTION_RAW,
    0,
    (VOID **)&DbxDefault,
    &DbxDefaultSize
  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Locate Dbx Binary File in FV!\n", __FUNCTION__));
    ASSERT (FALSE);
  }

  mSecureBootPayload[0] = (SECURE_BOOT_PAYLOAD_INFO) {
    .KekPtr = KekDefault,
    .KekSize = KekDefaultSize,
    .DbPtr = Db3PDefault,
    .DbSize = Db3PDefaultSize,
    .DbxPtr = DbxDefault,
    .DbxSize = DbxDefaultSize,
    .PkPtr = SigListBuffer,
    .PkSize = DataSize
  };

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
  VOID  *SigListBuffer;

  // This should be initialized from constructor, so casting here is fine
  SigListBuffer = (VOID *)mSecureBootPayload[0].PkPtr;
  if (SigListBuffer != NULL) {
    FreePool (SigListBuffer);
  }

  return EFI_SUCCESS;
}
