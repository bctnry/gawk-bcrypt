@load "bcrypt"

BEGIN {
	hash1 = bcrypt::hash_with_salt("abcdefg", 5)
	print hash1
	hash2 = bcrypt::hash_with_salt("abcdefg", 10)
	print hash2
	print bcrypt::check_hash("abcdefg", hash1)
	print bcrypt::check_hash("abcdefg", hash2)
	print bcrypt::check_hash("abcdefk", hash1)
	print bcrypt::check_hash("abcdefk", hash2)
}
