from pydantic import BaseModel


class OllamaTestRequest(BaseModel):
    base_url: str
    model: str


class FileScanRequest(BaseModel):
    path: str


class AnalysisOptions(BaseModel):
    include_http: bool = True
    include_tls: bool = True
    include_dns: bool = False
    deep_dive: bool = False


class OllamaConfig(BaseModel):
    base_url: str
    model: str


class AnalysisStartRequest(BaseModel):
    ollama: OllamaConfig
    file_path: str
    goal: str
    options: AnalysisOptions = AnalysisOptions()
