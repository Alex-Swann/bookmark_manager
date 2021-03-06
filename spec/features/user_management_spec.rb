
feature 'User sign up' do
  scenario 'I can sign up as a new user' do
    expect{ sign_up }.to change(User, :count).by(1)
    expect(page).to have_content('Welcome, alice@example.com')
    expect(User.first.email).to eq('alice@example.com')
  end

  scenario 'requires a matching confirmation password' do
    expect { sign_up(password_confirmation: 'wrong') }.not_to change(User, :count)
    expect(current_path).to eq('/users')
    expect(page).to have_content 'Password does not match the confirmation'
  end

  scenario "can't sign in with blank email" do
    expect{ sign_up(email: nil) }.not_to change(User, :count)
  end

  scenario "I can't sign up with an invalid email address" do
    expect{ sign_up(email: 'invalid@email') }.not_to change(User, :count)
  end

  scenario "user can't sign up twice to prevent duplicates" do
    expect{ sign_up }.to change(User, :count).by(1)
    expect{ sign_up }.not_to change(User, :count)
    expect(page).to have_content 'Email is already taken'
  end

end