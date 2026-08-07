/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { generateCaptchaTerms, operators } from '../../routes/captcha'
const expect = chai.expect

describe('captcha', () => {
  describe('generateCaptchaTerms', () => {
    it('generates operand terms within the expected 1-10 range', () => {
      for (let i = 0; i < 1000; i++) {
        const { firstTerm, secondTerm, thirdTerm } = generateCaptchaTerms()

        expect(firstTerm).to.be.within(1, 10)
        expect(secondTerm).to.be.within(1, 10)
        expect(thirdTerm).to.be.within(1, 10)
      }
    })

    it('selects operators only from the defined operator set', () => {
      for (let i = 0; i < 1000; i++) {
        const { firstOperator, secondOperator } = generateCaptchaTerms()

        expect(operators).to.include(firstOperator)
        expect(operators).to.include(secondOperator)
      }
    })
  })
})
