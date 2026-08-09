describe('/#/administration', () => {
  beforeEach(() => {
    cy.login({
      email: 'admin',
      password: 'admin123'
    })
  })
  describe('challenge "adminSection"', () => {
    it('should not expose the administration route', () => {
      cy.visit('/#/administration')
      cy.get('app-administration').should('not.exist')
    })
  })

  describe('challenge "fiveStarFeedback"', () => {
    it.skip('should be possible for any admin user to delete feedback', () => {
      cy.visit('/#/administration')
      cy.wait(1000)
      cy.get('.mat-mdc-cell.mat-column-remove > button').first().click()
      cy.expectChallengeSolved({ challenge: 'Five-Star Feedback' })
    })
  })
})
