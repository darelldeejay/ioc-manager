login_js_content = """
document.addEventListener('DOMContentLoaded', () => {
  const formInner = document.querySelector('.boxy-form-inner');
  const inputs = document.querySelectorAll('#boxy-login-form input');
  const buttons = document.querySelectorAll('#boxy-login-form button');
  const refresh = document.querySelector('.boxy-refresh');
  const forgot = document.querySelector('.boxy-forgot');
  const msg = document.querySelector('em.small-forgot');

  let step = 0;

  function rotateForm(toStep) {
    step = toStep;
    const rotation = ['rotateY(-90deg)', 'rotateX(-90deg)', 'rotateX(-180deg)', 'rotateX(90deg)'];
    formInner.style.transform = rotation[toStep] || 'none';
  }

  buttons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const input = btn.previousElementSibling;
      if (input && input.value.trim() === '') {
        formInner.classList.add('shake');
        msg.style.display = 'block';
        return;
      }
      formInner.classList.remove('shake');
      msg.style.display = 'none';
      rotateForm(parseInt(btn.dataset.step) + 1);
    });
  });

  refresh.addEventListener('click', () => {
    inputs.forEach(input => input.value = '');
    rotateForm(0);
    msg.style.display = 'none';
  });

  forgot.addEventListener('click', (e) => {
    e.preventDefault();
    rotateForm(3); // Email input
  });

  document.querySelector('.glyphicon-user').addEventListener('click', () => {
    document.querySelector('input[name=username]').focus();
  });
});
"""

with open(login_js_path, "w", encoding="utf-8") as f:
    f.write(login_js_content)

login_js_path
