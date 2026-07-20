/*
 * Accessible multi-step checkout controller (vanilla JS, no dependencies).
 *
 * A11Y architecture:
 * - Steps are <section hidden> — `hidden` removes them from BOTH the visual
 *   layout and the accessibility tree, so screen readers never wander into
 *   an inactive step and Tab never reaches its controls.
 * - On every step change, focus moves to the new step's heading
 *   (tabindex="-1") and the aria-live status region announces
 *   "Step X of 3: <name>". Keyboard and SR users always know where they are.
 * - Validation: on "Continue", invalid fields get aria-invalid="true" and an
 *   inline message wired via aria-describedby; the error summary (role=alert)
 *   receives focus and lists each error as a link that focuses its field.
 * - No keyboard traps: only native focusable elements are used, in DOM order.
 *
 * SECURITY note (defense in depth even in a demo): review-step values are
 * rendered exclusively with textContent — never innerHTML — so user input
 * can't inject markup (XSS-safe output encoding at the render context).
 */
(function () {
  "use strict";

  var form = document.getElementById("checkout-form");
  var statusLive = document.getElementById("status-live");
  var errorSummary = document.getElementById("error-summary");
  var errorSummaryList = document.getElementById("error-summary-list");
  var progressItems = Array.prototype.slice.call(
    document.querySelectorAll("#progress-list li"),
  );

  var STEPS = [
    { id: "step-1", name: "Shipping details" },
    { id: "step-2", name: "Payment" },
    { id: "step-3", name: "Review your order" },
  ];
  var current = 0;

  /* ------------------------------ validation ----------------------------- */

  var validators = {
    "full-name": function (v) {
      return v.trim() ? "" : "Enter your full name";
    },
    email: function (v) {
      if (!v.trim()) return "Enter your email address";
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim())
        ? ""
        : "Enter an email address in the correct format, like name@example.com";
    },
    address: function (v) {
      return v.trim() ? "" : "Enter your street address";
    },
    city: function (v) {
      return v.trim() ? "" : "Enter your city";
    },
    "postal-code": function (v) {
      if (!v.trim()) return "Enter your postal code";
      return /^[A-Za-z0-9][A-Za-z0-9 -]{1,9}$/.test(v.trim())
        ? ""
        : "Enter a valid postal code";
    },
    country: function (v) {
      return v ? "" : "Select your country";
    },
    "card-name": function (v) {
      return v.trim() ? "" : "Enter the name on the card";
    },
    "card-number": function (v) {
      var digits = v.replace(/[\s-]/g, "");
      if (!digits) return "Enter your card number";
      return /^\d{16}$/.test(digits) ? "" : "Enter the 16-digit card number";
    },
    "card-expiry": function (v) {
      if (!v.trim()) return "Enter the expiry date";
      var m = /^(0[1-9]|1[0-2])\/(\d{2})$/.exec(v.trim());
      if (!m) return "Enter the expiry date as MM/YY, like 04/28";
      var year = 2000 + Number(m[2]);
      var endOfMonth = new Date(year, Number(m[1]), 1);
      return endOfMonth > new Date() ? "" : "The expiry date must be in the future";
    },
    "card-cvc": function (v) {
      if (!v.trim()) return "Enter the security code";
      return /^\d{3,4}$/.test(v.trim()) ? "" : "Enter the 3 or 4 digit security code";
    },
  };

  function setFieldError(field, message) {
    var errorEl = document.getElementById(field.id + "-error");
    if (!errorEl) return;
    if (message) {
      field.setAttribute("aria-invalid", "true");
      errorEl.textContent = message;
      errorEl.hidden = false;
    } else {
      field.removeAttribute("aria-invalid");
      errorEl.textContent = "";
      errorEl.hidden = true;
    }
  }

  function validateStep(stepIndex) {
    var section = document.getElementById(STEPS[stepIndex].id);
    var fields = section.querySelectorAll("input:not([type=radio]), select");
    var errors = [];
    Array.prototype.forEach.call(fields, function (field) {
      var validate = validators[field.id];
      if (!validate) return;
      var message = validate(field.value);
      setFieldError(field, message);
      if (message) errors.push({ id: field.id, message: message });
    });
    return errors;
  }

  function showErrorSummary(errors) {
    errorSummaryList.textContent = "";
    errors.forEach(function (error) {
      var li = document.createElement("li");
      var link = document.createElement("a");
      link.href = "#" + error.id;
      link.textContent = error.message;
      // Focus the field (not just scroll to it) so the user can fix it
      // immediately; preventDefault stops the hash from polluting history.
      link.addEventListener("click", function (event) {
        event.preventDefault();
        document.getElementById(error.id).focus();
      });
      li.appendChild(link);
      errorSummaryList.appendChild(li);
    });
    errorSummary.hidden = false;
    // Focus makes SRs announce the alert content and puts keyboard users
    // one Tab away from the first fix-it link.
    errorSummary.focus();
  }

  function clearErrorSummary() {
    errorSummary.hidden = true;
    errorSummaryList.textContent = "";
  }

  /* ------------------------------ navigation ----------------------------- */

  function renderProgress() {
    progressItems.forEach(function (item, index) {
      if (index === current) {
        item.setAttribute("aria-current", "step");
      } else {
        item.removeAttribute("aria-current");
      }
      item.classList.toggle("completed", index < current);
      // Completed state in TEXT for AT, not just the visual style.
      var label = item.querySelector(".visually-hidden");
      var base = " — step " + (index + 1) + " of 3";
      label.textContent = index < current ? base + " (completed)" : base;
    });
  }

  function goToStep(index) {
    STEPS.forEach(function (step, i) {
      document.getElementById(step.id).hidden = i !== index;
    });
    document.getElementById("step-done").hidden = true;
    current = index;
    renderProgress();
    clearErrorSummary();
    if (index === 2) fillReview();

    var heading = document.querySelector("#" + STEPS[index].id + " h2");
    heading.focus();
    statusLive.textContent =
      "Step " + (index + 1) + " of 3: " + STEPS[index].name;
  }

  function fillReview() {
    var value = function (id) {
      return document.getElementById(id).value.trim();
    };
    var shippingMethod = document.querySelector(
      "input[name=shipping-method]:checked",
    );
    var shippingLabel = document
      .querySelector("label[for=" + shippingMethod.id + "]")
      .textContent.trim();
    // Only the LAST four card digits ever reach the review DOM.
    var last4 = value("card-number").replace(/[\s-]/g, "").slice(-4);

    renderList("review-shipping", [
      ["Name", value("full-name")],
      ["Email", value("email")],
      ["Address", value("address") + ", " + value("city") + " " + value("postal-code")],
      ["Country", value("country")],
    ]);
    renderList("review-payment", [
      ["Delivery", shippingLabel],
      ["Card", "Ending in " + last4],
      ["Name on card", value("card-name")],
    ]);
  }

  function renderList(id, pairs) {
    var dl = document.getElementById(id);
    dl.textContent = "";
    pairs.forEach(function (pair) {
      var dt = document.createElement("dt");
      dt.textContent = pair[0];
      var dd = document.createElement("dd");
      dd.textContent = pair[1]; // textContent = XSS-safe output encoding.
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
  }

  /* -------------------------------- wiring -------------------------------- */

  form.addEventListener("click", function (event) {
    var button = event.target.closest("button");
    if (!button) return;

    if (button.dataset.action === "next") {
      var errors = validateStep(current);
      if (errors.length > 0) {
        showErrorSummary(errors);
        return;
      }
      goToStep(current + 1);
    } else if (button.dataset.action === "back") {
      goToStep(current - 1);
    } else if (button.dataset.goto) {
      goToStep(Number(button.dataset.goto) - 1);
    }
  });

  // Clear a field's error as soon as the user fixes it — stale error text
  // that no longer matches the value confuses screen-reader users most.
  form.addEventListener("input", function (event) {
    var field = event.target;
    if (field.getAttribute("aria-invalid") === "true" && validators[field.id]) {
      var message = validators[field.id](field.value);
      if (!message) setFieldError(field, "");
    }
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault(); // demo: nothing is transmitted anywhere
    var errors = validateStep(current);
    if (errors.length > 0) {
      showErrorSummary(errors);
      return;
    }
    STEPS.forEach(function (step) {
      document.getElementById(step.id).hidden = true;
    });
    var done = document.getElementById("step-done");
    done.hidden = false;
    document.getElementById("done-heading").focus();
    statusLive.textContent = "Order placed successfully.";
  });

  renderProgress();
})();
