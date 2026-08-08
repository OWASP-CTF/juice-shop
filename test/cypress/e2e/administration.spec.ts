describe('/#/administration', () => {
  beforeEach(() => {
    cy.login({
      email: 'admin',
      password: 'admin123'
    })
  })
  describe('challenge "adminSection"', () => {
    it('should not expose the administration section in the public application', () => {
      cy.visit('/#/administration')
      cy.get('app-administration').should('not.exist')
    })
  })

  describe('challenge "fiveStarFeedback"', () => {
    it('should be possible for any admin user to delete feedback through the API', () => {
      cy.request('/api/Feedbacks').then((response) => {
        const feedback = response.body.data.find((entry: { rating: number }) => entry.rating === 5)
        cy.request({
          method: 'DELETE',
          url: `/api/Feedbacks/${feedback.id}`,
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        })
      })
      cy.expectChallengeSolved({ challenge: 'Five-Star Feedback' })
    })
  })
})
