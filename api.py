import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles  
from fastapi.templating import Jinja2Templates 
import asyncio

app = FastAPI(title="NetSentry Dashboard API")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="template")
alerts_db = []

#qua riceviamo gli allarmi
@app.post("/api/receive_alerts")
async def receive_alert(alert_data: dict):
    "viene chiamato ogni volta che c'è un allarme"
    print(f"Ricevuto allarme: {alert_data}")
    alerts_db.append(alert_data)
    #manentimo solo 50 allarmi
    if len(alerts_db) > 50:
        alerts_db.pop(0)
    return {"status": "success", "alert_received": alert_data}

#qua invece inviamo gli alert al browser
@app.get("/api/alerts")
async def send_alert():
    "serve ad aggiornare in pratica"
    return {"alerts": alerts_db}



@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request): 
    """
    Serve la pagina web principale usando il file
    templates/index.html
    """
   
    return templates.TemplateResponse("index.html", {"request": request})


if __name__ == "__main__":
    print("Avvio del server Dashboard su http://127.0.0.1:8000")
    uvicorn.run("dashboard:app", host="127.0.0.1", port=8000, reload=True)

