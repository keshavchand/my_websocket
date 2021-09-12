#if !defined(WIN_SHA_H)
#define WIN_SHA_H

#include <wincrypt.h>

bool ws_sha1_hash_base64(const char *data1, long data1_len, const char *data2, long data2_len, char *output_string, int string_len){
  HCRYPTPROV Prov = 0;
  BOOL success = CryptAcquireContextA(&Prov, NULL, NULL, PROV_RSA_FULL, 0);
  if(success) { }else{
    //Error checking
    return false;
  }

  HCRYPTHASH Hash;
  success = CryptCreateHash(Prov, CALG_SHA1, 0, 0, &Hash);
  if (success) { }else{
    CryptReleaseContext(Prov, 0);
    return false;
  }

  success = CryptHashData(Hash, (const BYTE*) data1, data1_len, 0);
  success = CryptHashData(Hash, (const BYTE*) data2, data2_len , 0);
  if (success) { }else{
    CryptDestroyHash(Hash);
    CryptReleaseContext(Prov, 0);
    return false;
  }
#define SHA1_SIZE 20 
  BYTE hash[SHA1_SIZE];
  int hash_len = SHA1_SIZE;
  success = CryptGetHashParam(Hash, HP_HASHVAL, hash, (DWORD*) &hash_len, 0);
  if (success) { }else{
    CryptDestroyHash(Hash);
    CryptReleaseContext(Prov, 0);
    return false;
  }

  CryptBinaryToStringA(hash, hash_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, output_string,(DWORD *) &string_len);

  CryptDestroyHash(Hash);
  CryptReleaseContext(Prov, 0);
  return true;
}

#endif
