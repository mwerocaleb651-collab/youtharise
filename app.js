document.getElementById("signup-form").addEventListener("submit", function(e) {
  const password = document.querySelector("input[name='password']").value;
  const confirmPassword = document.querySelector("input[name='confirm_password']").value;
  const message = document.getElementById("signup-message");

  if (password !== confirmPassword) {
    e.preventDefault();
    message.textContent = "Passwords do not match!";
  }
});
