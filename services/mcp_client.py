"""MCP Client using official Python MCP SDK for communication with Check Point MCP servers"""

import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import subprocess

# Import official MCP SDK
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

@dataclass
class MCPTool:
    """Represents an MCP tool exposed by a server"""
    name: str
    description: str
    input_schema: Dict[str, Any]

class MCPClient:
    """Client for communicating with MCP servers using official Python MCP SDK"""
    
    def __init__(self):
        self.sessions: Dict[str, ClientSession] = {}
    
    async def initialize_and_connect(self, server_name: str, package_name: str, env_vars: Dict[str, str] = None) -> bool:
        """Initialize and connect to an MCP server
        
        Args:
            server_name: Name of the server
            package_name: NPM package name
            env_vars: Environment variables for the server
            
        Returns:
            True if successful
        """
        try:
            # Create server parameters
            server_params = StdioServerParameters(
                command="npx",
                args=[package_name],
                env=env_vars or {}
            )
            
            # Create stdio client and connect
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # Initialize the session
                    await session.initialize()
                    
                    # Store session for later use
                    self.sessions[server_name] = session
                    
                    return True
                    
        except Exception as e:
            print(f"[MCPClient] Error connecting to {server_name}: {e}")
            return False
    
    async def list_tools(self, server_name: str) -> List[MCPTool]:
        """List available tools from MCP server
        
        Args:
            server_name: Name of the server
            
        Returns:
            List of MCPTool objects
        """
        if server_name not in self.sessions:
            return []
        
        try:
            session = self.sessions[server_name]
            result = await session.list_tools()
            
            tools = []
            for tool in result.tools:
                tools.append(MCPTool(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=tool.inputSchema
                ))
            return tools
            
        except Exception as e:
            print(f"[MCPClient] Error listing tools for {server_name}: {e}")
            return []
    
    async def call_tool(self, server_name: str, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call a specific tool on the MCP server
        
        Args:
            server_name: Name of the server
            tool_name: Name of the tool to call
            arguments: Arguments to pass to the tool
            
        Returns:
            The tool's response
        """
        if server_name not in self.sessions:
            return {"error": f"No session for server {server_name}"}
        
        try:
            session = self.sessions[server_name]
            result = await session.call_tool(tool_name, arguments=arguments or {})
            
            # Convert result to dictionary
            return {
                "content": result.content,
                "isError": result.isError if hasattr(result, 'isError') else False
            }
            
        except Exception as e:
            print(f"[MCPClient] Error calling tool {tool_name} on {server_name}: {e}")
            return {"error": str(e)}
    
    async def list_resources(self, server_name: str) -> List[Dict[str, Any]]:
        """List available resources from MCP server
        
        Args:
            server_name: Name of the server
            
        Returns:
            List of resource info dictionaries
        """
        if server_name not in self.sessions:
            return []
        
        try:
            session = self.sessions[server_name]
            result = await session.list_resources()
            
            resources = []
            for resource in result.resources:
                resources.append({
                    "uri": resource.uri,
                    "name": resource.name,
                    "description": resource.description or "",
                    "mimeType": resource.mimeType if hasattr(resource, 'mimeType') else None
                })
            return resources
            
        except Exception as e:
            print(f"[MCPClient] Error listing resources for {server_name}: {e}")
            return []
    
    async def read_resource(self, server_name: str, resource_uri: str) -> Dict[str, Any]:
        """Read a specific resource from the MCP server
        
        Args:
            server_name: Name of the server
            resource_uri: URI of the resource to read
            
        Returns:
            The resource content
        """
        if server_name not in self.sessions:
            return {"error": f"No session for server {server_name}"}
        
        try:
            session = self.sessions[server_name]
            result = await session.read_resource(resource_uri)
            
            return {
                "uri": result.uri,
                "contents": result.contents
            }
            
        except Exception as e:
            print(f"[MCPClient] Error reading resource {resource_uri} from {server_name}: {e}")
            return {"error": str(e)}
    
    async def close(self, server_name: str):
        """Close connection to a server
        
        Args:
            server_name: Name of the server to disconnect from
        """
        if server_name in self.sessions:
            try:
                # The session will be closed when the context manager exits
                del self.sessions[server_name]
            except Exception as e:
                print(f"[MCPClient] Error closing session for {server_name}: {e}")

# Synchronous wrapper functions for use in non-async contexts
def sync_initialize_and_connect(client: MCPClient, server_name: str, package_name: str, env_vars: Dict[str, str] = None) -> bool:
    """Synchronous wrapper for initialize_and_connect"""
    return asyncio.run(client.initialize_and_connect(server_name, package_name, env_vars))

def sync_list_tools(client: MCPClient, server_name: str) -> List[MCPTool]:
    """Synchronous wrapper for list_tools"""
    return asyncio.run(client.list_tools(server_name))

def sync_call_tool(client: MCPClient, server_name: str, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Synchronous wrapper for call_tool"""
    return asyncio.run(client.call_tool(server_name, tool_name, arguments))

def sync_list_resources(client: MCPClient, server_name: str) -> List[Dict[str, Any]]:
    """Synchronous wrapper for list_resources"""
    return asyncio.run(client.list_resources(server_name))

def sync_read_resource(client: MCPClient, server_name: str, resource_uri: str) -> Dict[str, Any]:
    """Synchronous wrapper for read_resource"""
    return asyncio.run(client.read_resource(server_name, resource_uri))
