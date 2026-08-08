describe('/rest/products/reviews', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })

  describe('challenge "NoSQL DoS"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'R4nd0m-Capybara-7!Quartz' })
    })
    it('should reject command injection without solving the challenge', () => {
      cy.request({
        url: '/rest/products/sleep(1000)/reviews',
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.equal(400)
        expect(response.body).to.deep.equal({ error: 'Wrong Params' })
      })
      cy.request('/api/Challenges/?name=NoSQL DoS').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "NoSQL Exfiltration"', () => {
    it('should reject order query injection without solving the challenge', () => {
      cy.request({
        url: '/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27',
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.equal(400)
        expect(response.body).to.deep.equal({ error: 'Wrong Param' })
      })
      cy.request('/api/Challenges/?name=NoSQL Exfiltration').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "NoSQL Manipulation"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'R4nd0m-Capybara-7!Quartz' })
    })

    it('should reject a selector injection without changing reviews', () => {
      cy.request('/rest/products/1/reviews').then((before) => {
        const snapshot = before.body.data.map(({ _id, message }: { _id: string, message: string }) => ({ _id, message }))
        cy.window().then((win) => cy.request({
          method: 'PATCH',
          url: '/rest/products/reviews',
          failOnStatusCode: false,
          headers: {
            Authorization: `Bearer ${win.localStorage.getItem('token')}`
          },
          body: {
            id: { $ne: -1 },
            message: 'NoSQL Injection!'
          }
        })).its('status').should('equal', 400)
        cy.request('/rest/products/1/reviews').then((after) => {
          const current = after.body.data.map(({ _id, message }: { _id: string, message: string }) => ({ _id, message }))
          expect(current).to.deep.equal(snapshot)
        })
      })
      cy.request('/api/Challenges/?name=NoSQL Manipulation').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
      })
    })
  })

  describe('challenge "Forged Review"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should not edit another user\'s review', () => {
      cy.request('/rest/products/1/reviews').then((before) => {
        const review = before.body.data.find(({ author }: { author: string }) => author !== 'mc.safesearch@juice-sh.op')
        expect(review).to.exist
        cy.window().then((win) => cy.request({
          method: 'PATCH',
          url: '/rest/products/reviews',
          headers: {
            Authorization: `Bearer ${win.localStorage.getItem('token')}`
          },
          body: { id: review._id, message: 'Forged edit' }
        })).then((response) => {
          expect(response.status).to.equal(200)
          expect(response.body.modified).to.equal(0)
        })
        cy.request('/rest/products/1/reviews').then((after) => {
          const unchanged = after.body.data.find(({ _id }: { _id: string }) => _id === review._id)
          expect(unchanged.message).to.equal(review.message)
        })
      })
      cy.request('/api/Challenges/?name=Forged Review').then((response) => {
        expect(response.body.data[0].solved).to.equal(false)
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
