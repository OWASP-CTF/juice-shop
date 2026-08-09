describe('/rest/products/reviews', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })

  describe('challenge "NoSQL DoS"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })
    it('should no longer be possible to inject a command into the get route', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(() => {
            void fetch(
              `${Cypress.config('baseUrl')}/rest/products/sleep(1000)/reviews`,
              {
                method: 'GET',
                headers: {
                  'Content-type': 'text/plain'
                }
              }
            )
          })
          cy.request('/api/Challenges/?key=noSqlCommandChallenge').then((res) => {
            expect(res.body.data[0].solved).to.equal(false)
          })
        }
      })
    })
  })

  describe('challenge "NoSQL Exfiltration"', () => {
    it('should no longer be possible to inject and get all the orders', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(async () => {
            await fetch(
              `${Cypress.config('baseUrl')}/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27`,
              {
                method: 'GET',
                headers: {
                  'Content-type': 'text/plain'
                }
              }
            )
          })
          cy.request('/api/Challenges/?key=noSqlOrdersChallenge').then((res) => {
            expect(res.body.data[0].solved).to.equal(false)
          })
        }
      })
    })
  })

  describe('challenge "NoSQL Manipulation"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })

    it('should no longer be possible to inject a selector into the update route', () => {
      cy.window().then(async () => {
        await fetch(`${Cypress.config('baseUrl')}/rest/products/reviews`, {
          method: 'PATCH',
          headers: {
            'Content-type': 'application/json',
            Authorization: `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({
            id: { $ne: -1 },
            message: 'NoSQL Injection!'
          })
        })
      })
      cy.request('/api/Challenges/?key=noSqlReviewsChallenge').then((res) => {
        expect(res.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "Forged Review"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should no longer be possible to edit another user\u2019s review', () => {
      cy.visit('/')
      cy.window().then(async () => {
        const response = await fetch(
          `${Cypress.config('baseUrl')}/rest/products/1/reviews`,
          {
            method: 'GET',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
        if (response.status === 200) {
          const responseJson = await response.json()
          const reviewId = responseJson.data[0]._id
          await editReview(reviewId)
        }

        async function editReview (reviewId: string) {
          const response = await fetch(
            `${Cypress.config('baseUrl')}/rest/products/reviews`,
            {
              method: 'PATCH',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ id: reviewId, message: 'injected' })
            }
          )
          if (response.status === 200) {
            console.log('Success')
          }
        }
      })
      cy.request('/api/Challenges/?key=forgedReviewChallenge').then((res) => {
        expect(res.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "Multiple Likes"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should be possible to like reviews multiple times', () => {
      cy.visit('/')
      cy.window().then(async () => {
        async function sendPostRequest (reviewId: string) {
          const anotherResponse = await fetch(
            `${Cypress.config('baseUrl')}/rest/products/reviews`,
            {
              method: 'POST',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ id: reviewId })
            }
          )
          if (anotherResponse.status === 200) {
            console.log('Success')
          }
        }

        const response = await fetch(
          `${Cypress.config('baseUrl')}/rest/products/1/reviews`,
          {
            method: 'GET',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
        if (response.status === 200) {
          const responseJson = await response.json()
          const reviewId = responseJson.data[0]._id

          void sendPostRequest(reviewId)
          void sendPostRequest(reviewId)
          void sendPostRequest(reviewId)
        }
      })
      cy.expectChallengeSolved({ challenge: 'Multiple Likes' })
    })
  })
})
