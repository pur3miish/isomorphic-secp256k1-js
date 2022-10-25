import TestDirector from 'test-director/TestDirector.mjs'
import test_get_public_key from './public_key.test.mjs'
import test_recover_public_key from './recover_public_key.test.mjs'
import test_sign from './sign.test.mjs'

const tests = new TestDirector()
test_get_public_key(tests)
test_sign(tests)
test_recover_public_key(tests)
tests.run()
