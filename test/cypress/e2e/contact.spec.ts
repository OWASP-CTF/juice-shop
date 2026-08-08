import type { Product as ProductConfig } from '../../../lib/config.types'

describe('/#/contact', () => {
  beforeEach(() => {
    cy.visit('/#/contact')
    solveNextCaptcha()
  })

  describe('challenge "forgedFeedback"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.visit('/#/contact')
      solveNextCaptcha()
    })

    it('should be possible to provide feedback as another user', () => {
      cy.get('#userId').then(function ($element) {
        $element[0].removeAttribute('hidden')
        $element[0].removeAttribute('class')
      })

      cy.get('#userId').clear().type('2')
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.get('#comment').type('Picard stinks!')
      cy.get('#submitButton').should('not.be.disabled').click()

      cy.visit('/#/administration')

      cy.get(
        '.customer-table > .mat-mdc-table > :nth-child(8) > .cdk-column-user'
      ).then(($val) => {
        if ($val.text() !== ' 2') {
          cy.get(
            '.customer-table > .mat-mdc-table > :nth-child(9) > .cdk-column-user'
          ).should('contain.text', '2')
        } else {
          expect($val.text()).contain('2')
        }
      })

      cy.expectChallengeSolved({ challenge: 'Forged Feedback' })
    })
  })

  describe('challenge "persistedXssFeedback"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.visit('/#/contact')
      solveNextCaptcha()
    })

    // Cypress alert bug
    // The challenge also passes but its just that cypress freezes and is unable to perform any action
    xit('should be possible to trick the sanitization with a masked XSS attack', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
          cy.get('#comment').type(
            '<<script>Foo</script>iframe src="javascript:alert(`xss`)">'
          )
          cy.get('#submitButton').should('not.be.disabled').click()

          cy.visit('/#/about')
          cy.on('window:alert', (t) => {
            expect(t).to.equal('xss')
          })

          cy.visit('/#/administration')
          cy.on('window:alert', (t) => {
            expect(t).to.equal('xss')
          })
          cy.expectChallengeSolved({ challenge: 'Server-side XSS Protection' })
        }
      })
    })
  })

  describe('challenge "vulnerableComponent"', () => {
    it('should be possible to post known vulnerable component(s) as feedback', () => {
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.get('#comment').type('sanitize-html 1.4.2 is non-recursive.')
      cy.get('#comment').type('express-jwt 0.1.3 has broken crypto.')

      cy.get('#submitButton').should('not.be.disabled').click()
      cy.expectChallengeSolved({ challenge: 'Vulnerable Library' })
    })
  })

  describe('challenge "weirdCrypto"', () => {
    it('should be possible to post weird crypto algorithm/library as feedback', () => {
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.get('#comment').type(
        'The following libraries are bad for crypto: z85, base85, md5 and hashids'
      )
      cy.get('#submitButton').should('not.be.disabled').click()
      cy.expectChallengeSolved({ challenge: 'Weird Crypto' })
    })
  })

  describe('challenge "typosquattingNpm"', () => {
    it('should be possible to post typosquatting NPM package as feedback', () => {
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.get('#comment').type(
        'You are a typosquatting victim of this NPM package: epilogue-js'
      )
      cy.get('#submitButton').should('not.be.disabled').click()
      cy.expectChallengeSolved({ challenge: 'Legacy Typosquatting' })
    })
  })

  describe('challenge "typosquattingAngular"', () => {
    it('should be possible to post typosquatting NPM package as feedback', () => {
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.get('#comment').type(
        'You are a typosquatting victim of this NPM package: ngy-cookie'
      )
      cy.get('#submitButton').should('not.be.disabled').click()
      cy.expectChallengeSolved({ challenge: 'Frontend Typosquatting' })
    })
  })

  describe('challenge "hiddenImage"', () => {
    it('should be possible to post hidden character name as feedback', () => {
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.get('#comment').type(
        'Pickle Rick is hiding behind one of the support team ladies'
      )
      cy.get('#submitButton').should('not.be.disabled').click()
      cy.expectChallengeSolved({ challenge: 'Steganography' })
    })
  })

  describe('challenge "zeroStars"', () => {
    it('should be possible to post feedback with zero stars by double-clicking rating widget', () => {
      cy.visit('/')
      cy.window().then(async () => {
        const response = await fetch(
          `${Cypress.config('baseUrl')}/rest/captcha/`,
          {
            method: 'GET',
            cache: 'no-cache',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
        if (response.status === 200) {
          const responseJson = await response.json()
          console.log(responseJson)

          await sendPostRequest(responseJson)
        }

        async function sendPostRequest (captcha: {
          captchaId: number
          captcha: string
        }) {
          const response = await fetch(
            `${Cypress.config('baseUrl')}/api/Feedbacks`,
            {
              method: 'POST',
              cache: 'no-cache',
              headers: {
                'Content-type': 'application/json'
              },
              body: JSON.stringify({
                captchaId: captcha.captchaId,
                captcha: solveCaptcha(captcha.captcha),
                comment: 'Comment',
                rating: 0
              })
            }
          )
          if (response.status === 201) {
            console.log('Success')
          }
        }
      })
      cy.expectChallengeSolved({ challenge: 'Zero Stars' })
    })
  })

  describe('challenge "captchaBypass"', () => {
    it('should not disclose CAPTCHA answers or allow CAPTCHA replay', () => {
      cy.window().then(async () => {
        const response = await fetch(
          `${Cypress.config('baseUrl')}/rest/captcha/`,
          {
            method: 'GET',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
        const captcha = await response.json()
        expect(captcha.answer).to.equal(undefined)
        const payload = JSON.stringify({
          captchaId: captcha.captchaId,
          captcha: solveCaptcha(captcha.captcha),
          comment: 'Replay attempt',
          rating: 3
        })
        const options = {
          method: 'POST',
          cache: 'no-cache' as RequestCache,
          headers: { 'Content-type': 'application/json' },
          body: payload
        }

        expect((await fetch(`${Cypress.config('baseUrl')}/api/Feedbacks`, options)).status).to.equal(201)
        expect((await fetch(`${Cypress.config('baseUrl')}/api/Feedbacks`, options)).status).to.equal(401)
      })
    })
  })

  describe('challenge "supplyChainAttack"', () => {
    it('should be possible to post GitHub issue URL reporting malicious eslint-scope package as feedback', () => {
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.get('#comment').type(
        'Turn on 2FA! Now!!! https://github.com/eslint/eslint-scope/issues/39'
      )
      cy.get('#submitButton').should('not.be.disabled').click()
      cy.expectChallengeSolved({ challenge: 'Supply Chain Attack' })
    })
  })

  describe('challenge "dlpPastebinDataLeak"', () => {
    it('should be possible to post dangerous ingredients of unsafe product as feedback', () => {
      cy.get('#rating').type('{rightarrow}{rightarrow}{rightarrow}')
      cy.task<ProductConfig>('GetPastebinLeakProduct').then((pastebinLeakProduct: ProductConfig) => {
        cy.get('#comment').type(
          pastebinLeakProduct.keywordsForPastebinDataLeakChallenge ? pastebinLeakProduct.keywordsForPastebinDataLeakChallenge.toString() : '?'
        )
      })
      cy.get('#submitButton').should('not.be.disabled').click()
      cy.expectChallengeSolved({ challenge: 'Leaked Unsafe Product' })
    })
  })
})

function solveNextCaptcha () {
  cy.get('#captcha')
    .should('be.visible')
    .invoke('text')
    .then((val) => {
      cy.get('#captchaControl').clear()
      // eslint-disable-next-line no-eval
      const answer = eval(val).toString()
      cy.get('#captchaControl').type(answer)
    })
}

function solveCaptcha (expression: string): string {
  const match = expression.match(/^(\d+)([*+-])(\d+)([*+-])(\d+)$/)
  if (!match) throw new Error('Unexpected CAPTCHA expression')
  const [, first, firstOperator, second, secondOperator, third] = match
  const calculate = (left: number, operator: string, right: number) => operator === '*' ? left * right : operator === '+' ? left + right : left - right
  if (secondOperator === '*' && firstOperator !== '*') {
    return calculate(Number(first), firstOperator, calculate(Number(second), secondOperator, Number(third))).toString()
  }
  return calculate(calculate(Number(first), firstOperator, Number(second)), secondOperator, Number(third)).toString()
}
