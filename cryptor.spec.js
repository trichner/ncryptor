var assert = require('assert');

describe('Cryptor', function() {

	const cryptor = require('./cryptor');
	describe('Encrypt', () => {
		it('should be idempotent', function() {
			const pw = '1234'
			const txt = 'Hello World! Its a töst. With Ā and ø.'
			const ciphertext = cryptor.encrypt(pw, txt);
			const plaintext = cryptor.decrypt(pw, ciphertext);
			assert.equal(txt, plaintext);
		});

		it('ciphertext should change, no ECB', function() {
			const pw = '1234'
			const txt = 'Hello World! Its a töst. With Ā and ø.'
			const c1 = cryptor.encrypt(pw, txt);
			const c2 = cryptor.encrypt(pw, txt);
			assert.notEqual(c1, c2);
		});

		it('version should be 1', function() {
			const pw = '1234'
			const txt = 'Hello World! Its a töst. With Ā and ø.'
			const c1 = cryptor.encrypt(pw, txt);
			assert.equal(c1.substring(0, 2), '01');
		});
	});

	describe('Decrypt', () => {
		it('should fail on wrong password', function() {
			const pw = '1234'
			const txt = 'Hello World! Its a töst. With Ā and ø.'
			const ciphertext = cryptor.encrypt(pw, txt);

			function decrypt() {
				cryptor.decrypt('wrongPw', ciphertext);
			}

			assert.throws(decrypt, Error, 'Error thrown');
		});

		it('should fail on wrong version', function() {
			const pw = '1234'
			const txt = 'Hello World! Its a töst. With Ā and ø.'
			const ciphertext = cryptor.encrypt(pw, txt);
			const tampered = '1' + ciphertext.substring(1);

			function decrypt() {
				cryptor.decrypt(pw, tampered);
			}

			assert.throws(decrypt, Error, 'Error thrown');
		});

		it('should fail on tampered ciphertext', function() {
			const pw = '1234'
			const txt = 'Hello World! Its a töst. With Ā and ø.'
			const ciphertext = cryptor.encrypt(pw, txt);
			const cipherbytes = Buffer.from(ciphertext, 'hex');
			let i = 0;

			function flipBit(buf) {
				const c = Buffer.from(cipherbytes);
				const bytePos = Math.floor(i / 8);
				let tamperedByte = c[bytePos] ^ (0x1 << (i % 8));
				c[bytePos] = tamperedByte;
				return c;
			}

			function decrypt() {
				const tampered = flipBit(cipherbytes).toString('hex');
				cryptor.decrypt(pw, tampered);
			}

			for (; i < cipherbytes.length * 8; i++) {
				assert.throws(decrypt, Error, 'Error thrown ' + i);
			}
		});
	})

});