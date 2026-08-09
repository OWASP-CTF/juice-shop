describe('/api', () => {
  describe('challenge "restfulXss"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })

    // Regression test: product description is now always sanitized server-side
    // (see models/product.ts), so the "API-only XSS" challenge can never be solved.
    it('should sanitize XSS payloads in product description and never solve the challenge', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/api/Products`,
              {
                method: 'POST',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json',
                  Authorization: `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                  name: 'RestXSS',
                  description: '<iframe src="javascript:alert(`xss`)">',
                  price: 47.11
                })
              }
            )
            const product = await response.json()
            expect(product.data.description).to.not.contain('<iframe')
          })

          cy.request({
            method: 'GET',
            url: '/api/Challenges/?name=API-only XSS',
            timeout: 60000
          }).then((res) => {
            const challenge = res.body.data[0]
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            expect(challenge.solved).to.be.false
          })
        }
      })
    })
  })

  describe('challenge "changeProduct"', () => {
    it('should be possible to change product via PUT request without being logged in', () => {
      cy.task<number>('GetTamperingProductId').then((tamperingProductId: number) => {
        cy.task<string>('GetOverwriteUrl').then((overwriteUrl: string) => {
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/api/Products/${tamperingProductId}`,
              {
                method: 'PUT',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json'
                },
                body: JSON.stringify({
                  description: `<a href="${overwriteUrl}" target="_blank">More...</a>`
                })
              }
            )
            assert.equal(response.status, 200)
          })

          cy.visit('/#/search')
        })
      })
      cy.expectChallengeSolved({ challenge: 'Product Tampering' })
    })
  })
})

describe('/rest/saveLoginIp', () => {
  describe('challenge "httpHeaderXss"', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'admin123'
      })
    })

    // Regression test: lastLoginIp is now always sanitized server-side
    // (see routes/saveLoginIp.ts), so the "HTTP-Header XSS" challenge can never be solved.
    it('should sanitize the True-Client-IP header and never solve the challenge', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/rest/saveLoginIp`,
              {
                method: 'GET',
                cache: 'no-cache',
                headers: {
                  Authorization: `Bearer ${localStorage.getItem('token')}`,
                  'True-Client-IP': '<iframe src="javascript:alert(`xss`)">'
                }
              }
            )
            const body = await response.json()
            expect(body.data.lastLoginIp).to.not.contain('<iframe')
          })

          cy.request({
            method: 'GET',
            url: '/api/Challenges/?name=HTTP-Header XSS',
            timeout: 60000
          }).then((res) => {
            const challenge = res.body.data[0]
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            expect(challenge.solved).to.be.false
          })
        }
      })
    })
  })

  it('should not be possible to save log-in IP when not logged in', () => {
    cy.request({ url: '/rest/saveLoginIp', failOnStatusCode: false }).then(
      (response) => {
        console.log(response.body)
        expect(response.body).to.equal('Unauthorized')
      }
    )
  })
})
