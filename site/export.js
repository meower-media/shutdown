const loginBox = document.getElementById("login-box");
const loginForm = document.getElementById("login-form");
const loginError = document.getElementById("login-error");
const exportBox = document.getElementById("export-box");
const exportDownloadButton = document.getElementById("export-download");
const exportDeleteButton = document.getElementById("export-delete");

loginBox.hidden = false;

loginForm.addEventListener("submit", async (event) => {
	event.preventDefault();

	const data = new FormData(loginForm);

	const loginResponse = await (
		await fetch("https://api.meower.org/auth/login", {
			method: "POST",
			body: JSON.stringify(Object.fromEntries(data)),
		})
	).json();

	if (loginResponse.error) {
		if (loginResponse.type === "mfaRequired") {
			loginError.hidden = false;
			loginError.innerText = "2FA Required";
		} else if (loginResponse.type === "Unauthorized") {
			loginError.hidden = false;
			loginError.innerText = "Invalid username or password";
		} else if (loginResponse.type === "Internal") {
			loginError.hidden = false;
			loginError.innerText = "Internal error";
		} else {
			loginError.hidden = false;
			loginError.innerText = `Unknown error: ${loginResponse.type}`;
		}
	} else {
		loginBox.hidden = true;
		loginError.hidden = true;

		onLogin(loginResponse.token);
	}
});

async function onLogin(token) {
	const post = (
		await (
			await fetch("https://api.meower.org/home", {
				headers: {
					token,
				},
			})
		).json()
	).autoget.pop();

	const exportDataLink = post.p.match(/https?:\/\/[^\s]+/)[0];

	exportDownloadButton.addEventListener("click", async () => {
		const temporaryDownloadLink = document.createElement("a");
		temporaryDownloadLink.href = exportDataLink;
		temporaryDownloadLink.download = "export.zip";
		temporaryDownloadLink.click();
	});

	exportDeleteButton.addEventListener("click", async () => {
		await onDelete(token);
	});

	exportBox.hidden = false;
}

async function onDelete(token) {
	const yesno = confirm(
		"Are you sure you want to delete your account? This is permanent.",
	);

	if (yesno) {
		const resp = await (
			await fetch("https://api.meower.org/me", {
				method: "DELETE",
				headers: {
					token,
				},
			})
		).json();

		if (resp.error) {
			alert("Error deleting account: " + resp.type);
		} else {
			alert("Account deleted successfully");
		}
	}
}
