import os.path

import nmap
from diamond_shovel.function.task import PipelineWorkerScope
from diamond_shovel.plugins import PluginInitContext, events
from nmap import PortScannerError

import nmap_worker
from nmapper.nmap_container import plugin_di


def on_pipeline_init(evt: events.PipelineInitEvent):
    evt.pipeline.add(PipelineWorkerScope.INFO_COLLECTION, "nmapper", lambda ctx: nmap_worker.handle_task(ctx), 30)

def load(load_context: PluginInitContext):
    cfg = load_context.config
    plugin_di["ports"] = cfg.get("nmap", "ports")
    plugin_di["thread_size"] = cfg.getint("nmap", "threads")
    plugin_di["extra_flags"] = cfg.get("nmap", "extra_flags")
    plugin_di["data_folder"] = load_context.data_folder

    try:
        nmap.PortScanner()
    except PortScannerError: # nmap not found
        load_context.extract_resource("nmap", True)
        os.chmod(load_context.data_folder / "nmap", 0o755)

    events.register_event(events.PipelineInitEvent, on_pipeline_init)

