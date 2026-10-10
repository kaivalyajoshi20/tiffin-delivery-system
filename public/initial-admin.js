const form=document.getElementById("setup-form");
const status=document.getElementById("status");
const button=document.getElementById("submit");
form.addEventListener("submit",async(event)=>{
  event.preventDefault();
  status.textContent="Preparing secure request…";
  button.disabled=true;
  try{
    const csrfResponse=await fetch("/api/csrf",{credentials:"same-origin",cache:"no-store"});
    if(!csrfResponse.ok)throw new Error("Could not initialize a secure session. Refresh the page and try again.");
    const csrf=await csrfResponse.json();
    const data=Object.fromEntries(new FormData(form).entries());
    const response=await fetch("/api/initial-admin",{
      method:"POST",
      credentials:"same-origin",
      cache:"no-store",
      headers:{"Content-Type":"application/json","X-CSRF-Token":csrf.csrfToken},
      body:JSON.stringify(data)
    });
    const result=await response.json().catch(()=>({message:"Unexpected server response."}));
    if(!response.ok)throw new Error(result.message||"Admin setup failed.");
    form.reset();
    status.textContent=result.message||"Admin account created.";
  }catch(error){
    status.textContent=error.message||"Request failed. Please try again.";
  }finally{button.disabled=false}
});
